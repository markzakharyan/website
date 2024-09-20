const express = require('express');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const { isAuthenticated } = require('../middleware/auth');
const router = express.Router();

const pool = new Pool({
  connectionString: process.env.NODE_ENV === 'production' ? process.env.DATABASE_PRIVATE_URL : process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// Update profile
router.post('/update-profile', isAuthenticated, async (req, res) => {
  const {
    firstname,
    lastname,
    email,
    birthday,
    birthdayOptIn,
    currentPassword,
    newPassword,
  } = req.body;

  try {
    const userResult = await pool.query("SELECT * FROM users WHERE id = $1", [
      req.session.userId,
    ]);
    const user = userResult.rows[0];

    if (newPassword) {
      const isMatch = await bcrypt.compare(currentPassword, user.password);
      if (!isMatch) {
        return res.status(400).json({ error: "Current password is incorrect" });
      }
    }

    let updateQuery = `
      UPDATE users 
      SET firstname = $1, lastname = $2, email = $3, birthday = $4, birthdayOptIn = $5
    `;
    let queryParams = [
      firstname,
      lastname,
      email,
      birthday,
      birthdayOptIn === "on",
    ];

    if (newPassword) {
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      updateQuery += `, password = $${queryParams.length + 1}`;
      queryParams.push(hashedPassword);
    }

    updateQuery += ` WHERE id = $${queryParams.length + 1}`;
    queryParams.push(req.session.userId);

    await pool.query(updateQuery, queryParams);

    res.json({ message: "Profile updated successfully" });
  } catch (error) {
    console.error("Error updating profile:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get birthdays
router.get('/get_birthdays', async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, firstname, birthday FROM users WHERE birthdayOptIn = true"
    );
    const birthdays = result.rows.map((user) => ({
      id: user.id,
      name: user.firstname,
      bday: user.birthday,
    }));
    res.json(birthdays);
  } catch (err) {
    console.error("Error fetching birthdays:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

module.exports = router;