const mongoose = require('mongoose');

const ownerSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  siteKey: { type: String, required: true, unique: true },
  password: { type: String, required: function() { return !this.googleId; } }, // required unless googleId is present
  googleId: { type: String }, // for Google OAuth users
  theme: { type: mongoose.Schema.Types.Mixed, default: {} },
});

module.exports = mongoose.model('Owner', ownerSchema); 