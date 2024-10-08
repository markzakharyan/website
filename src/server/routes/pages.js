const express = require('express');
const { Pool } = require('pg');
const { isAuthenticated, isAdmin, isKayla } = require('../middleware/auth');
const { get } = require('./auth');
const router = express.Router();

const pool = new Pool({
  connectionString: process.env.NODE_ENV === 'production' ? process.env.DATABASE_PRIVATE_URL : process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// Home page
router.get('/', async (req, res) => {
  try {
    const user = await getUser(req);
    if (user) {
      if (user.isadmin) {
        res.render('pages/index_loggedin_admin', { user: user, success: req.session.successMessage });
      } else {
        if (user.email === process.env.KAYLA_EMAIL) {
          res.render('pages/index_kayla', { user: user, success: req.session.successMessage });
        } else {
          res.render('pages/index_loggedin', { user: user, success: req.session.successMessage });
        }
      }
      delete req.session.successMessage;
    } else {
      res.render('pages/index', { success: req.session.successMessage });
      delete req.session.successMessage;
    }
  } catch (err) {
    console.error('Error fetching user:', err);
    res.status(500).render('pages/error', { error: 'Internal Server Error' });
  }
});

const getUser = async (req) => {
  let user;
  if (req.session.userId) {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.session.userId]);
    user = result.rows[0];
  }
  return user;
}

// Birthdays page
router.get('/birthdays', async (req, res) => {
  const user = await getUser(req)
  res.render('pages/birthdays', {user: user});
});

// Fourier visualization page
router.get('/fourier', async (req, res) => {
  const user = await getUser(req)
  res.render('pages/fourier', {user: user});
});

router.get('/fourier_new', async (req, res) => {
  const user = await getUser(req)
  res.render('pages/fourier_new', {user: user});
});

router.get('/lattice', async (req, res) => {
  const user = await getUser(req)
  res.render('pages/lattice', {user: user});
});

// Manage users page (admin only)
router.get('/manage_users', isAuthenticated, isAdmin, (req, res) => {
  res.render('pages/manage_users');
});

// Manage profile page
router.get('/manage-profile', isAuthenticated, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.session.userId]);
    const user = result.rows[0];
    res.render('pages/manage_user', { user });
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).render('pages/error', { error: 'Internal server error' });
  }
});

// Registration page
router.get('/register', (req, res) => {
  res.render('pages/register');
});

router.get('/kayla', isKayla, (req, res) => {
  res.render('pages/kayla');
});


// Reset password page
router.get('/reset-password', (req, res) => {
  res.render('pages/reset_password');
});

// Reset password form page
router.get('/reset/:token', async (req, res) => {
  const { token } = req.params;
  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE reset_token = $1 AND reset_token_expiry > $2',
      [token, Date.now()]
    );
    if (result.rows.length === 0) {
      return res.render('pages/reset_password', { error: 'Invalid or expired reset token.' });
    }
    res.render('pages/reset_password_form', { token });
  } catch (error) {
    console.error('Error checking reset token:', error);
    res.render('pages/reset_password', { error: 'An error occurred. Please try again later.' });
  }
});

// Request API Key page
router.get('/request-api-key', isAuthenticated, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT api_key FROM users WHERE id = $1',
      [req.session.userId]
    );
    const user = result.rows[0];
    res.render('pages/request_api_key', {
      hasApiKey: !!user.api_key, // Check if an API key exists
      apiKeyGenerated: false,    // Indicates if a new API key was just generated
    });
  } catch (error) {
    console.error('Error fetching API key:', error);
    res.status(500).render('pages/error', { error: 'Internal server error' });
  }
});

module.exports = router;