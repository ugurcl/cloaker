const mongoose = require('mongoose');
const User = require('./models/User');
const VisitorLog = require('./models/VisitorLog');
const RedirectUrl = require('./models/RedirectUrl');

const connectDB = async () => {
  try {
    const mongoURI = process.env.MONGODB_URI || 'mongodb://localhost:27017/cloaker';
    await mongoose.connect(mongoURI);
    console.log('MongoDB connected successfully');
  } catch (error) {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  }
};

const initDatabase = async () => {
  try {
    await connectDB();
    
    const adminExists = await User.findOne({ username: 'admin' });
    if (!adminExists) {
      const adminUser = new User({
        username: 'admin',
        password: 'admin123'
      });
      await adminUser.save();
      console.log('Default admin user created (username: admin, password: admin123)');
    }
    
    const defaultRedirectExists = await RedirectUrl.findOne({ isActive: true });
    if (!defaultRedirectExists) {
      const hasAnyUrl = await RedirectUrl.findOne();
      if (!hasAnyUrl) {
        const defaultRedirect = new RedirectUrl({
          name: 'Default Redirect',
          url: 'https://example.com',
          isActive: true
        });
        await defaultRedirect.save();
        console.log('Default redirect URL created');
      }
    }
  } catch (error) {
    console.error('Database initialization error:', error);
    throw error;
  }
};

const logVisitor = async (visitorData) => {
  try {
    const { ip, country, userAgent, isBot, isMobile, action } = visitorData;
    const visitorLog = new VisitorLog({
      ip,
      country,
      userAgent,
      isBot,
      isMobile,
      action
    });
    await visitorLog.save();
  } catch (error) {
    console.error('Error logging visitor:', error);
  }
};

const getVisitorLogs = async (limit = 100) => {
  try {
    const logs = await VisitorLog.find()
      .sort({ createdAt: -1 })
      .limit(limit)
      .lean();
    
    return logs.map(log => ({
      ...log,
      visited_at: log.createdAt,
      is_bot: log.isBot,
      is_mobile: log.isMobile,
      user_agent: log.userAgent
    }));
  } catch (error) {
    console.error('Error getting visitor logs:', error);
    return [];
  }
};

const getVisitorStats = async () => {
  try {
    const [
      totalVisits,
      botVisits,
      mobileVisits,
      redirectedVisits,
      topCountries,
      dailyVisits
    ] = await Promise.all([
      VisitorLog.countDocuments(),
      VisitorLog.countDocuments({ isBot: true }),
      VisitorLog.countDocuments({ isMobile: true }),
      VisitorLog.countDocuments({ action: 'redirected' }),
      VisitorLog.aggregate([
        { $match: { country: { $ne: null } } },
        { $group: { _id: '$country', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 },
        { $project: { country: '$_id', count: 1, _id: 0 } }
      ]),
      VisitorLog.aggregate([
        {
          $group: {
            _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
            count: { $sum: 1 }
          }
        },
        { $sort: { _id: -1 } },
        { $limit: 7 },
        { $project: { date: '$_id', count: 1, _id: 0 } }
      ])
    ]);

    return {
      totalVisits,
      botVisits,
      mobileVisits,
      redirectedVisits,
      topCountries,
      dailyVisits
    };
  } catch (error) {
    console.error('Error getting visitor stats:', error);
    return {
      totalVisits: 0,
      botVisits: 0,
      mobileVisits: 0,
      redirectedVisits: 0,
      topCountries: [],
      dailyVisits: []
    };
  }
};

const getRedirectUrls = async () => {
  try {
    const urls = await RedirectUrl.find().sort({ createdAt: -1 }).lean();
    return urls.map(url => ({
      ...url,
      id: url._id.toString(),
      is_active: url.isActive,
      created_at: url.createdAt
    }));
  } catch (error) {
    console.error('Error getting redirect URLs:', error);
    return [];
  }
};

const addRedirectUrl = async (name, url, theme = 'business') => {
  try {
    const redirectUrl = new RedirectUrl({ name, url, theme });
    const savedUrl = await redirectUrl.save();
    return {
      id: savedUrl._id.toString(),
      name: savedUrl.name,
      url: savedUrl.url,
      theme: savedUrl.theme,
      isActive: savedUrl.isActive
    };
  } catch (error) {
    console.error('Error adding redirect URL:', error);
    throw error;
  }
};

const updateRedirectUrl = async (id, name, url) => {
  try {
    await RedirectUrl.findByIdAndUpdate(id, { name, url });
  } catch (error) {
    console.error('Error updating redirect URL:', error);
    throw error;
  }
};

const setActiveRedirectUrl = async (id) => {
  try {
    await RedirectUrl.updateMany({}, { isActive: false });
    await RedirectUrl.findByIdAndUpdate(id, { isActive: true });
  } catch (error) {
    console.error('Error setting active redirect URL:', error);
    throw error;
  }
};

const getActiveRedirectUrl = async () => {
  try {
    const activeUrl = await RedirectUrl.findOne({ isActive: true });
    if (activeUrl) {
      return {
        url: activeUrl.url,
        theme: activeUrl.theme || 'business'
      };
    }
    return {
      url: process.env.REDIRECT_URL || 'https://example.com',
      theme: 'business'
    };
  } catch (error) {
    console.error('Error getting active redirect URL:', error);
    return {
      url: process.env.REDIRECT_URL || 'https://example.com',
      theme: 'business'
    };
  }
};

const deleteRedirectUrl = async (id) => {
  try {
    await RedirectUrl.findByIdAndDelete(id);
  } catch (error) {
    console.error('Error deleting redirect URL:', error);
    throw error;
  }
};

const verifyUser = async (username, password) => {
  try {
    const user = await User.findOne({ username });
    if (!user) return null;
    
    const isValid = await user.comparePassword(password);
    return isValid ? { id: user._id.toString(), username: user.username } : null;
  } catch (error) {
    console.error('Error verifying user:', error);
    return null;
  }
};

const changePassword = async (userId, newPassword) => {
  try {
    const user = await User.findById(userId);
    if (!user) throw new Error('User not found');
    
    user.password = newPassword;
    await user.save();
  } catch (error) {
    console.error('Error changing password:', error);
    throw error;
  }
};

// Security-focused database functions
const updateUserLastLogin = async (userId, ip, userAgent) => {
  try {
    const user = await User.findById(userId);
    if (user) {
      user.last_login = new Date();
      user.last_login_ip = ip;
      user.last_login_user_agent = userAgent;
      user.login_count = (user.login_count || 0) + 1;
      await user.save();
    }
  } catch (error) {
    console.error('Update last login error:', error);
  }
};

const getUserById = async (userId) => {
  try {
    return await User.findById(userId).select('-password');
  } catch (error) {
    console.error('Get user error:', error);
    throw error;
  }
};

const getSecurityAlerts = async (limit = 50) => {
  try {
    const suspiciousLogs = await VisitorLog.find({
      $or: [
        { user_agent: /bot|crawler|spider/i },
        { action: 'blocked' }
      ]
    })
    .sort({ timestamp: -1 })
    .limit(limit);

    return suspiciousLogs.map(log => ({
      title: 'Suspicious Activity Detected',
      description: `${log.action} from ${log.country || 'Unknown'} - ${log.user_agent}`,
      timestamp: log.timestamp,
      severity: log.is_bot ? 'medium' : 'low',
      ip: log.ip
    }));
  } catch (error) {
    console.error('Get security alerts error:', error);
    return [];
  }
};

const getSecurityAlertCount = async () => {
  try {
    return await VisitorLog.countDocuments({
      timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) },
      $or: [
        { user_agent: /bot|crawler|spider/i },
        { action: 'blocked' }
      ]
    });
  } catch (error) {
    console.error('Get security alert count error:', error);
    return 0;
  }
};

const getBlockedIpCount = async () => {
  try {
    const blockedIps = await VisitorLog.distinct('ip', {
      timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) },
      action: 'blocked'
    });
    return blockedIps.length;
  } catch (error) {
    console.error('Get blocked IP count error:', error);
    return 0;
  }
};

const getActiveSessionCount = async () => {
  try {
    return 1; // Current logged in admin
  } catch (error) {
    console.error('Get active session count error:', error);
    return 0;
  }
};

const logSecurityEvent = async (eventData) => {
  try {
    const securityLog = new VisitorLog({
      ip: eventData.ip,
      country: eventData.country || 'Unknown',
      user_agent: eventData.userAgent,
      is_bot: false,
      is_mobile: false,
      action: 'security_event',
      timestamp: new Date(),
      details: eventData.details
    });
    
    await securityLog.save();
    console.log(`[SECURITY EVENT LOGGED] ${JSON.stringify(eventData)}`);
  } catch (error) {
    console.error('Log security event error:', error);
  }
};

const cleanupOldLogs = async (daysToKeep = 90) => {
  try {
    const cutoffDate = new Date(Date.now() - daysToKeep * 24 * 60 * 60 * 1000);
    const result = await VisitorLog.deleteMany({
      timestamp: { $lt: cutoffDate }
    });
    
    console.log(`Cleaned up ${result.deletedCount} old log entries older than ${daysToKeep} days`);
    return result.deletedCount;
  } catch (error) {
    console.error('Cleanup old logs error:', error);
    return 0;
  }
};

module.exports = {
  initDatabase,
  logVisitor,
  getVisitorLogs,
  getVisitorStats,
  getRedirectUrls,
  addRedirectUrl,
  updateRedirectUrl,
  setActiveRedirectUrl,
  getActiveRedirectUrl,
  deleteRedirectUrl,
  verifyUser,
  changePassword,
  updateUserLastLogin,
  getUserById,
  getSecurityAlerts,
  getSecurityAlertCount,
  getBlockedIpCount,
  getActiveSessionCount,
  logSecurityEvent,
  cleanupOldLogs
};