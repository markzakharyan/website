const express = require('express');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const { isAuthenticated, isAdmin } = require('../middleware/auth');
const router = express.Router();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// Get all users (admin only)
router.get('/', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, firstname, lastname, birthday, birthdayOptIn, isadmin FROM users'
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Add a new user (admin only)
router.post('/', isAuthenticated, isAdmin, async (req, res) => {
  const { email, firstname, lastname, birthday, birthdayOptIn, isadmin, password } = req.body;

  if (!email || !firstname || !lastname || !password) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (email, firstname, lastname, birthday, birthdayOptIn, isadmin, password)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id`,
      [email, firstname, lastname, birthday, birthdayOptIn, isadmin, hashedPassword]
    );

    res.status(201).json({
      id: result.rows[0].id,
      message: 'User added successfully',
    });
  } catch (error) {
    console.error('Error adding new user:', error);
    res.status(500).json({ error: 'Error adding new user' });
  }
});

// Update an existing user (admin only)
router.put('/:id', isAuthenticated, isAdmin, async (req, res) => {
  const userId = req.params.id;
  const { email, firstname, lastname, birthday, birthdayOptIn, isadmin, password } = req.body;

  if (!email || !firstname || !lastname) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    let updateFields = [email, firstname, lastname, birthday, birthdayOptIn, isadmin, userId];
    let sql = `
      UPDATE users 
      SET email = $1, firstname = $2, lastname = $3, birthday = $4, birthdayOptIn = $5, isadmin = $6
    `;

    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      updateFields.splice(6, 0, hashedPassword);
      sql += `, password = $7 WHERE id = $8`;
    } else {
      sql += ` WHERE id = $7`;
    }

    const result = await pool.query(sql, updateFields);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ message: 'User updated successfully' });
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ error: 'Error updating user' });
  }
});

// Delete a user (admin only)
router.delete('/:id', isAuthenticated, isAdmin, async (req, res) => {
  const userId = req.params.id;

  try {
    const result = await pool.query('DELETE FROM users WHERE id = $1', [userId]);
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    console.error('Error deleting user:', err);
    res.status(500).json({ error: 'Error deleting user' });
  }
});

module.exports = router;