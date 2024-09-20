const express = require('express');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { Pool } = require('pg');
const { sendResetPasswordEmail } = require('../utils/email');
const router = express.Router();

const pool = new Pool({
  connectionString: process.env.NODE_ENV === 'production' ? process.env.DATABASE_PRIVATE_URL : process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// Register
router.post('/register', async (req, res) => {
  const { email, firstname, lastname, password, confirm_password, birthday, birthdayOptIn } = req.body;

  if (!email || !firstname || !lastname || !password || !confirm_password) {
    return res.render("pages/register", { error: 'All required fields must be filled' });
  }

  if (password !== confirm_password) {
    return res.render("pages/register", { error: 'Passwords do not match' });
  }

  try {
    const userCheck = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (userCheck.rows.length > 0) {
      return res.render("pages/register", { error: 'Email already in use' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (email, firstname, lastname, password, birthday, birthdayOptIn, isadmin)
       VALUES ($1, $2, $3, $4, $5, $6, false) RETURNING id`,
      [email, firstname, lastname, hashedPassword, birthday || null, birthdayOptIn]
    );

    req.session.userId = result.rows[0].id;
    req.session.email = email;
    res.redirect("/");
  } catch (error) {
    console.error('Error in registration process:', error);
    res.render("pages/register", { error: 'An error occurred during registration' });
  }
});

// Login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (result.rows.length === 0) {
      return res.status(400).json({ success: false, error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (isMatch) {
      req.session.userId = user.id;
      req.session.email = user.email;
      return res.json({ success: true, user: user });
    } else {
      return res.status(400).json({ success: false, error: 'Invalid credentials' });
    }
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ success: false, error: 'Error logging in' });
  }
});

// Logout
router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
      return res.status(500).json({ success: false, error: 'Error logging out' });
    }
    res.json({ success: true });
  });
});

// Request password reset
router.post('/reset-password', async (req, res) => {
  const { email } = req.body;

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "No account found with that email address." });
    }

    const user = result.rows[0];
    const resetToken = crypto.randomBytes(20).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour from now

    await pool.query(
      "UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE id = $3",
      [resetToken, resetTokenExpiry, user.id]
    );

    const resetUrl = `http://${req.headers.host}/reset/${resetToken}`;
    await sendResetPasswordEmail(user.email, resetUrl);

    res.render("pages/reset_password", {
      success: "A password reset link has been sent to your email.",
    });
  } catch (error) {
    console.error("Error in reset password process:", error);
    res.render("pages/reset_password", {
      error: "An error occurred. Please try again later.",
    });
  }
});

// Reset password
router.post('/reset/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE reset_token = $1 AND reset_token_expiry > $2",
      [token, Date.now()]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: "Invalid or expired reset token." });
    }

    const user = result.rows[0];
    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      "UPDATE users SET password = $1, reset_token = NULL, reset_token_expiry = NULL WHERE id = $2",
      [hashedPassword, user.id]
    );

    req.session.userId = user.id;
    req.session.successMessage = "Your password has been reset successfully. You have been automatically logged in.";
    res.redirect('/');

  } catch (error) {
    console.error("Error resetting password:", error);
    res.status(500).json({ error: "An error occurred. Please try again later." });
  }
});

module.exports = router;