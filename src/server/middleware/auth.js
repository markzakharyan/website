const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.NODE_ENV === 'production' ? process.env.DATABASE_PRIVATE_URL : process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// Middleware to check if the user is authenticated
function isAuthenticated(req, res, next) {
  if (req.session.userId) {
    return next();
  } else {
    // Store the original URL to redirect after login
    const redirectTo = req.originalUrl;
    return res.status(401).render('pages/unauthorized', { redirectTo });
  }
}

async function isKayla(req, res, next) {
  if (req.session.email === process.env.KAYLA_EMAIL) {
    next();
  } else {
    isAdmin(req, res, next);
  }
}

async function isAdmin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const result = await pool.query('SELECT isadmin FROM users WHERE id = $1', [req.session.userId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    if (!result.rows[0].isadmin) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
}

module.exports = { isAuthenticated, isAdmin, isKayla };