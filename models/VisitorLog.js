const mongoose = require('mongoose');

const visitorLogSchema = new mongoose.Schema({
  ip: {
    type: String,
    required: true
  },
  country: {
    type: String,
    default: null
  },
  userAgent: {
    type: String,
    required: true
  },
  isBot: {
    type: Boolean,
    default: false
  },
  isMobile: {
    type: Boolean,
    default: false
  },
  action: {
    type: String,
    enum: ['bot_page_shown', 'redirected', 'safe_page_shown'],
    required: true
  }
}, {
  timestamps: true
});

visitorLogSchema.index({ createdAt: -1 });
visitorLogSchema.index({ country: 1 });
visitorLogSchema.index({ isBot: 1 });
visitorLogSchema.index({ isMobile: 1 });
visitorLogSchema.index({ action: 1 });

module.exports = mongoose.model('VisitorLog', visitorLogSchema);