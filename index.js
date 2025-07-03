require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const Owner = require('./models/Owner');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const Submission = require('./models/Submission');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error('MongoDB connection error:', err));

// Test route
app.get('/', (req, res) => {
  res.send('Form Service API is running');
});

// Registration endpoint
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

  try {
    // Check if already registered
    let owner = await Owner.findOne({ email });
    if (owner) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    // Generate unique siteKey
    const siteKey = crypto.randomBytes(16).toString('hex');
    const hashedPassword = await bcrypt.hash(password, 10);
    owner = new Owner({ email, siteKey, password: hashedPassword });
    await owner.save();
    res.json({ siteKey });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed', details: err.message });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
  try {
    const owner = await Owner.findOne({ email });
    if (!owner) return res.status(400).json({ error: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, owner.password);
    if (!valid) return res.status(400).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ ownerId: owner._id, siteKey: owner.siteKey, email: owner.email }, process.env.JWT_SECRET || 'secret', { expiresIn: '7d' });
    res.json({ token, siteKey: owner.siteKey });
  } catch (err) {
    res.status(500).json({ error: 'Login failed', details: err.message });
  }
});

// Form submission endpoint
app.post('/api/submit', async (req, res) => {
  const { siteKey } = req.body;
  if (!siteKey) {
    return res.status(400).json({ error: 'siteKey is required' });
  }

  try {
    const owner = await Owner.findOne({ siteKey });
    if (!owner) {
      return res.status(404).json({ error: 'Invalid siteKey' });
    }

    // Save all fields from req.body (dynamic fields)
    const submissionData = { ...req.body };
    if (!submissionData.createdAt) submissionData.createdAt = new Date();
    console.log(submissionData);
    await Submission.create(submissionData);

    // Set up Nodemailer transporter
    const transporter = nodemailer.createTransport({
      service: process.env.EMAIL_SERVICE, // e.g., 'gmail'
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    // Build email content dynamically
    const fieldsHtml = Object.entries(submissionData)
      .filter(([key]) => key !== 'siteKey')
      .map(([key, value]) =>
        `<div style="margin-bottom: 18px;">
          <span style="display: inline-block; min-width: 80px; color: #6a82fb; font-weight: 600;">${key.charAt(0).toUpperCase() + key.slice(1)}:</span>
          <span style="color: #222;">${String(value).replace(/\n/g, '<br>')}</span>
        </div>`
      ).join('');

    // Email options
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: owner.email,
      subject: `New Form Submission`,
      text: Object.entries(submissionData).map(([k, v]) => `${k}: ${v}`).join('\n'),
      html: `
        <div style="background: #f4f6fb; min-height: 100vh; padding: 32px 0; font-family: 'Segoe UI', 'Roboto', Arial, sans-serif;">
          <div style="max-width: 480px; margin: 40px auto; background: #fff; border-radius: 18px; box-shadow: 0 6px 32px rgba(80, 80, 180, 0.10), 0 1.5px 6px rgba(80, 80, 180, 0.08); overflow: hidden;">
            <div style="background: linear-gradient(90deg, #6a82fb 0%, #fc5c7d 100%); padding: 24px 32px 16px 32px;">
              <h2 style="color: #fff; margin: 0; font-weight: 700; font-size: 1.6rem; letter-spacing: 1px;">🚀 New Form Submission</h2>
            </div>
            <div style="padding: 28px 32px 16px 32px;">
              ${fieldsHtml}
            </div>
            <div style="padding: 18px 32px 24px 32px; text-align: center;">
              <hr style="border: none; border-top: 1px solid #eee; margin: 0 0 12px 0;">
              <div style="font-size: 12px; color: #bbb;">
                Made with love by <a href="https://yashrajshitole.in" style="color: #bbb; text-decoration: underline;">Yashraj Shitole</a>
              </div>
            </div>
          </div>
        </div>
      `,
    };

    // Send email
    await transporter.sendMail(mailOptions);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to send email', details: err.message });
  }
});

// JWT Auth Middleware
function auth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    req.owner = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Get all submissions for a siteKey (protected)
app.get('/api/submissions', auth, async (req, res) => {
  const { siteKey } = req.query;
  if (!siteKey) return res.status(400).json({ error: 'siteKey is required' });
  if (req.owner.siteKey !== siteKey) return res.status(403).json({ error: 'Forbidden' });
  try {
    const submissions = await Submission.find({ siteKey }).sort({ createdAt: -1 });
    res.json({ submissions });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch submissions', details: err.message });
  }
});

// Get analytics for a siteKey (protected)
app.get('/api/analytics', auth, async (req, res) => {
  const { siteKey } = req.query;
  if (!siteKey) return res.status(400).json({ error: 'siteKey is required' });
  if (req.owner.siteKey !== siteKey) return res.status(403).json({ error: 'Forbidden' });
  try {
    const count = await Submission.countDocuments({ siteKey });
    const latest = await Submission.findOne({ siteKey }).sort({ createdAt: -1 });

    // Chart data: submissions per month for last 6 months
    const now = new Date();
    const months = [];
    for (let i = 5; i >= 0; i--) {
      const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
      months.push({
        year: d.getFullYear(),
        month: d.getMonth(),
        label: d.toLocaleString('default', { month: 'short' }),
      });
    }
    // Aggregate submissions by year/month
    const agg = await Submission.aggregate([
      { $match: { siteKey, createdAt: { $gte: new Date(now.getFullYear(), now.getMonth() - 5, 1) } } },
      { $group: {
        _id: { year: { $year: '$createdAt' }, month: { $month: '$createdAt' } },
        submissions: { $sum: 1 },
      } },
    ]);
    // Map to chartData
    const chartData = months.map(({ year, month, label }) => {
      const found = agg.find(a => a._id.year === year && a._id.month === month + 1);
      return { month: label, submissions: found ? found.submissions : 0 };
    });

    res.json({ count, latestSubmission: latest ? latest.createdAt : null, chartData });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch analytics', details: err.message });
  }
});

// Save theme for authenticated owner
app.post('/api/theme', auth, async (req, res) => {
  try {
    const owner = await Owner.findById(req.owner.ownerId);
    if (!owner) return res.status(404).json({ error: 'Owner not found' });
    owner.theme = req.body.theme || {};
    await owner.save();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save theme', details: err.message });
  }
});

// Get theme for authenticated owner
app.get('/api/theme', auth, async (req, res) => {
  try {
    const owner = await Owner.findById(req.owner.ownerId);
    if (!owner) return res.status(404).json({ error: 'Owner not found' });
    res.json({ theme: owner.theme || {} });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch theme', details: err.message });
  }
});

// Public: Get theme by siteKey (for widget embedding)
app.get('/api/theme/:siteKey', async (req, res) => {
  try {
    const owner = await Owner.findOne({ siteKey: req.params.siteKey });
    if (!owner) return res.status(404).json({ error: 'Owner not found' });
    res.json({ theme: owner.theme || {} });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch theme', details: err.message });
  }
});

// Passport Google OAuth setup
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:5000/api/auth/google/callback',
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let owner = await Owner.findOne({ email: profile.emails[0].value });
    if (!owner) {
      // Register new owner
      const siteKey = crypto.randomBytes(16).toString('hex');
      owner = new Owner({
        email: profile.emails[0].value,
        siteKey,
        googleId: profile.id, // Set googleId for Google users
        // Do NOT set password
      });
      await owner.save();
    }
    return done(null, owner);
  } catch (err) {
    return done(err, null);
  }
}));

app.use(passport.initialize());

// Google OAuth endpoints
app.get('/api/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/api/auth/google/callback',
  passport.authenticate('google', { session: false, failureRedirect: '/' }),
  (req, res) => {
    // Successful auth, issue JWT and redirect to frontend
    const token = jwt.sign({ ownerId: req.user._id, siteKey: req.user.siteKey, email: req.user.email }, process.env.JWT_SECRET || 'secret', { expiresIn: '7d' });
    // Redirect to frontend with token and siteKey as query params
    const frontendUrl = process.env.FRONTEND_URL;
    res.redirect(`${frontendUrl}/oauth-callback?token=${token}&siteKey=${req.user.siteKey}`);
  }
);

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 