const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');

// Rate limiting disabled - no limits
const loginLimiter = (req, res, next) => next();

// Rate limiting disabled - no limits  
const apiLimiter = (req, res, next) => next();

// Security headers middleware
const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
});

// CSRF Protection
const generateCSRFToken = (req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  res.locals.csrfToken = req.session.csrfToken;
  next();
};

const validateCSRF = (req, res, next) => {
  if (req.method === 'GET') return next();
  
  // Skip CSRF for logout if session exists (authenticated user)
  if (req.originalUrl === '/api/logout' && req.session && req.session.userId) {
    return next();
  }
  
  // Skip CSRF for login endpoint (will be handled by other security measures)
  if (req.originalUrl === '/api/login') {
    return next();
  }
  
  // If no session, skip CSRF (user not logged in yet)
  if (!req.session || !req.session.csrfToken) {
    return next();
  }
  
  const token = req.body.csrfToken || req.headers['x-csrf-token'];
  if (!token || token !== req.session.csrfToken) {
    return res.status(403).json({ error: 'CSRF token validation failed' });
  }
  next();
};

// Input sanitization
const sanitizeInput = (req, res, next) => {
  const sanitize = (obj) => {
    for (const key in obj) {
      if (typeof obj[key] === 'string') {
        // Remove dangerous characters and potential XSS
        obj[key] = obj[key]
          .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
          .replace(/javascript:/gi, '')
          .replace(/on\w+\s*=/gi, '')
          .trim();
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        sanitize(obj[key]);
      }
    }
  };

  if (req.body) sanitize(req.body);
  if (req.query) sanitize(req.query);
  if (req.params) sanitize(req.params);
  
  next();
};

// Brute force protection
const bruteForceTracks = new Map();

const brutForceProtection = (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  
  if (!bruteForceTracks.has(ip)) {
    bruteForceTracks.set(ip, { attempts: 0, lastAttempt: now, blocked: false });
  }
  
  const track = bruteForceTracks.get(ip);
  
  // Reset if more than 30 minutes passed
  if (now - track.lastAttempt > 30 * 60 * 1000) {
    track.attempts = 0;
    track.blocked = false;
  }
  
  // Check if IP is blocked
  if (track.blocked && now - track.lastAttempt < 30 * 60 * 1000) {
    return res.status(429).json({ error: 'IP blocked due to too many failed attempts. Try again later.' });
  }
  
  req.bruteForceTrack = track;
  next();
};

// Log failed attempts
const logFailedAttempt = (ip, username, userAgent) => {
  const now = new Date().toISOString();
  console.log(`[SECURITY WARNING] Failed login attempt: IP=${ip}, Username=${username}, UserAgent=${userAgent}, Time=${now}`);
  
  // Update brute force tracking
  if (bruteForceTracks.has(ip)) {
    const track = bruteForceTracks.get(ip);
    track.attempts += 1;
    track.lastAttempt = Date.now();
    
    // Block IP after 20 failed attempts
    if (track.attempts >= 20) {
      track.blocked = true;
      console.log(`[SECURITY ALERT] IP ${ip} has been blocked due to ${track.attempts} failed login attempts`);
    }
  }
};

// Log successful login
const logSuccessfulLogin = (ip, username, userAgent) => {
  const now = new Date().toISOString();
  console.log(`[SECURITY INFO] Successful login: IP=${ip}, Username=${username}, UserAgent=${userAgent}, Time=${now}`);
  
  // Reset brute force tracking on successful login
  if (bruteForceTracks.has(ip)) {
    bruteForceTracks.delete(ip);
  }
};

// Admin activity logger
const logAdminActivity = (req, res, next) => {
  if (req.session.userId) {
    const activity = {
      user: req.session.username,
      action: `${req.method} ${req.originalUrl}`,
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.headers['user-agent'],
      timestamp: new Date().toISOString()
    };
    
    console.log(`[ADMIN ACTIVITY] ${JSON.stringify(activity)}`);
  }
  next();
};

module.exports = {
  loginLimiter,
  apiLimiter,
  securityHeaders,
  generateCSRFToken,
  validateCSRF,
  sanitizeInput,
  brutForceProtection,
  logFailedAttempt,
  logSuccessfulLogin,
  logAdminActivity
};