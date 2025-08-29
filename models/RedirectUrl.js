const mongoose = require('mongoose');

const redirectUrlSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  url: {
    type: String,
    required: true,
    validate: {
      validator: function(v) {
        return /^https?:\/\/.+/.test(v);
      },
      message: 'Invalid URL format'
    }
  },
  theme: {
    type: String,
    enum: ['news', 'cybersecurity', 'blog', 'business'],
    default: 'business',
    required: true
  },
  isActive: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true
});

redirectUrlSchema.index({ isActive: 1 });
redirectUrlSchema.index({ createdAt: -1 });

module.exports = mongoose.model('RedirectUrl', redirectUrlSchema);