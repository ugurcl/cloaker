const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 50
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  role: {
    type: String,
    enum: ['admin', 'moderator', 'user'],
    default: 'admin'
  },
  email: {
    type: String,
    unique: true,
    sparse: true,
    lowercase: true
  },
  last_login: {
    type: Date
  },
  last_login_ip: {
    type: String
  },
  last_login_user_agent: {
    type: String
  },
  login_count: {
    type: Number,
    default: 0
  },
  failed_login_attempts: {
    type: Number,
    default: 0
  },
  locked_until: {
    type: Date
  },
  password_changed_at: {
    type: Date
  },
  two_factor_enabled: {
    type: Boolean,
    default: false
  },
  two_factor_secret: {
    type: String
  },
  backup_codes: [{
    type: String
  }],
  is_active: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Check if account is locked
userSchema.methods.isLocked = function() {
  return !!(this.locked_until && this.locked_until > Date.now());
};

// Increment failed login attempts
userSchema.methods.incFailedAttempts = function() {
  // If we have a previous lock that has expired, restart at 1
  if (this.locked_until && this.locked_until < Date.now()) {
    return this.updateOne({
      $unset: { locked_until: 1 },
      $set: { failed_login_attempts: 1 }
    });
  }
  
  const updates = { $inc: { failed_login_attempts: 1 } };
  
  // Lock account after 5 failed attempts for 2 hours
  if (this.failed_login_attempts + 1 >= 5 && !this.isLocked()) {
    updates.$set = { locked_until: Date.now() + 2 * 60 * 60 * 1000 }; // 2 hours
  }
  
  return this.updateOne(updates);
};

// Reset failed login attempts on successful login
userSchema.methods.resetFailedAttempts = function() {
  return this.updateOne({
    $unset: { 
      failed_login_attempts: 1,
      locked_until: 1
    }
  });
};

// Check if password was changed recently (for forced re-authentication)
userSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
  if (this.password_changed_at) {
    const changedTimestamp = parseInt(this.password_changed_at.getTime() / 1000, 10);
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

// Create index for performance
userSchema.index({ username: 1 });
userSchema.index({ email: 1 });
userSchema.index({ last_login: -1 });

module.exports = mongoose.model('User', userSchema);