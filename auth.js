const session = require('express-session');
const MongoStore = require('connect-mongo');
const crypto = require('crypto');

// Generate secure session secret if not provided
const generateSecureSecret = () => {
  return crypto.randomBytes(64).toString('hex');
};

const sessionMiddleware = session({
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/cloaker',
    touchAfter: 24 * 3600,
    ttl: 24 * 60 * 60 // 24 hours
  }),
  secret: process.env.SESSION_SECRET || generateSecureSecret(),
  name: 'sessionId', // Change default session name
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  },
  rolling: true // Reset expiry on activity
});

const requireAuth = (req, res, next) => {
  if (!req.session.userId) {
    return res.redirect('/admin/login?expired=1');
  }
  
  // Check session expiry
  if (req.session.expiresAt && Date.now() > req.session.expiresAt) {
    req.session.destroy();
    return res.redirect('/admin/login?expired=1');
  }
  
  // Update last activity
  req.session.lastActivity = Date.now();
  next();
};

const requireAuthApi = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized - Please login' });
  }
  
  // Check session expiry
  if (req.session.expiresAt && Date.now() > req.session.expiresAt) {
    req.session.destroy();
    return res.status(401).json({ error: 'Session expired' });
  }
  
  // Update last activity
  req.session.lastActivity = Date.now();
  next();
};

// Role-based access control
const requireRole = (roles) => {
  return (req, res, next) => {
    if (!req.session.userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    if (!roles.includes(req.session.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    next();
  };
};

// Session security enhancement
const enhanceSessionSecurity = (req, res, next) => {
  if (req.session && req.session.userId) {
    // Bind session to IP (optional, can cause issues with mobile users)
    if (process.env.STRICT_IP_BINDING === 'true') {
      const currentIP = req.ip || req.connection.remoteAddress;
      if (req.session.ipAddress && req.session.ipAddress !== currentIP) {
        req.session.destroy();
        return res.status(401).json({ error: 'Session security violation' });
      }
      req.session.ipAddress = currentIP;
    }
    
    // Bind session to user agent
    const currentUA = req.headers['user-agent'];
    if (req.session.userAgent && req.session.userAgent !== currentUA) {
      req.session.destroy();
      return res.status(401).json({ error: 'Session security violation' });
    }
    req.session.userAgent = currentUA;
  }
  next();
};

// Two-factor authentication helper
const requireTwoFactor = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  if (req.session.requires2FA && !req.session.twoFactorVerified) {
    return res.status(403).json({ error: 'Two-factor authentication required' });
  }
  
  next();
};

module.exports = {
  sessionMiddleware,
  requireAuth,
  requireAuthApi,
  requireRole,
  enhanceSessionSecurity,
  requireTwoFactor
};