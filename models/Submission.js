const mongoose = require('mongoose');

const submissionSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  message: { type: String, required: true },
  siteKey: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
}, { strict: false }); // Allow dynamic fields

module.exports = mongoose.model('Submission', submissionSchema); 