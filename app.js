const express = require("express");
const bcrypt = require("bcrypt");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const session = require('express-session');

const app = express();
const port = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

const isProduction = process.env.NODE_ENV === 'production';


// Set up session middleware
app.use(session({
  secret: 'your_secret_key', // Replace with a real secret key
  resave: false,
  saveUninitialized: false,
  cookie: { secure: isProduction } // Set to true if using https
}));

// Set EJS as the view engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Set up the database
const db = new sqlite3.Database("./users.db", (err) => {
  if (err) {
    console.error("Error opening database", err);
  } else {
    console.log("Connected to the SQLite database.");
    db.run(
      `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE,
      firstname TEXT,
      lastname TEXT,
      birthday TEXT,
      birthdayOptIn INTEGER,
      isadmin INTEGER,
      password TEXT
    )`,
      (err) => {
        if (err) {
          console.error("Error creating users table", err);
        } else {
          console.log("Users table ready");
        }
      }
    );
  }
});

// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
  if (req.session.userId) {
    next();
  } else {
    res.status(401).send("Unauthorized");
  }
}

// Middleware to check if user is admin
function isAdmin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).send("Unauthorized");
  }

  db.get(
    "SELECT isadmin FROM users WHERE id = ?",
    [req.session.userId],
    (err, user) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).send("Internal Server Error");
      }
      if (!user) {
        return res.status(404).send("User not found");
      }
      if (user.isadmin !== 1) {
        return res.status(403).send("Forbidden: Admin access required");
      }
      next();
    }
  );
}

// Serve home page
app.get("/", (req, res) => {
  db.get(
    "SELECT * FROM users WHERE id = ?",
    [req.session.userId],
    (err, user) => {
      if (err) {
        console.error("Error fetching user:", err);
        return res.status(500).send("Internal Server Error");
      }
      if (user) {
        if (user.isadmin) {
          res.render("index_loggedin_admin", { user: user });
        } else {
          res.render("index_loggedin", { user: user });
        }
      } else {
        req.session.destroy((err) => {
          if (err) {
            console.error("Error destroying session:", err);
          }
          res.render('index');
        });
      }
    }
  );
});

app.get("/roxy", (req, res) => {
  res.render("birthdays");
});

app.get("/birthdays", (req, res) => {
  res.render("birthdays");
});

app.get("/fourier", (req, res) => {
  res.render("fourier");
});

app.get("/manage_users", isAuthenticated, isAdmin, (req, res) => {
  res.render("manage_users");
});

// GET route to display the registration form
app.get('/register', (req, res) => {
  res.render('register');
});

// POST route to handle form submission
app.post('/register', async (req, res) => {
  const { email, firstname, lastname, password, confirm_password, birthday, birthdayOptIn } = req.body;

  // Check if required fields are present
  if (!email || !firstname || !lastname || !password || !confirm_password) {
    return res.render('register', { error: 'All required fields must be filled' });
  }

  if (password !== confirm_password) {
    return res.render('register', { error: 'Passwords do not match' });
  }

  try {
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
      if (err) {
        console.error(err);
        return res.render('register', { error: 'An error occurred' });
      }
      if (user) {
        return res.render('register', { error: 'Email already in use' });
      }

      try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const stmt = db.prepare(`
          INSERT INTO users (email, firstname, lastname, password, birthday, birthdayOptIn, isadmin)
          VALUES (?, ?, ?, ?, ?, ?, 0)
        `);

        stmt.run([
          email, 
          firstname, 
          lastname, 
          hashedPassword, 
          birthday || null, 
          birthdayOptIn ? 1 : 0
        ], function(err) {
          if (err) {
            console.error('Error registering new user:', err);
            return res.render('register', { error: 'Error registering user' });
          }
          
          req.session.userId = this.lastID;
          req.session.email = email;
          res.redirect('/');
        });

        stmt.finalize();
      } catch (hashError) {
        console.error('Error hashing password:', hashError);
        return res.render('register', { error: 'Error processing password' });
      }
    });
  } catch (error) {
    console.error('Error in registration process:', error);
    res.render('register', { error: 'An error occurred during registration' });
  }
});

// User login
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  console.log("Login attempt:", email);

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ success: false, error: "Error accessing database" });
    }
    if (!user) {
      console.log("User not found:", email);
      return res.status(400).json({ success: false, error: "Invalid credentials" });
    }
    try {
      const isMatch = await bcrypt.compare(password, user.password);
      console.log("Password match:", isMatch);
      if (isMatch) {
        req.session.userId = user.id;
        req.session.email = user.email;
        console.log("Login successful:", email);
        return res.json({ success: true, user: user });
      } else {
        console.log("Password mismatch:", email);
        return res.status(400).json({ success: false, error: "Invalid credentials" });
      }
    } catch (error) {
      console.error("Login error:", error);
      return res.status(500).json({ success: false, error: "Error logging in" });
    }
  });
});

// Logout
app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
      return res.status(500).json({ success: false, error: "Error logging out" });
    }
    res.json({ success: true });
  });
});

// GET /birthdays - Get all users who have opted in to share their birthday
app.get("/get_birthdays", (req, res) => {
  db.all(
    "SELECT id, firstname, birthday FROM users WHERE birthdayOptIn = 1",
    (err, users) => {
      if (err) {
        console.error("Error fetching birthdays:", err);
        return res.status(500).send("Internal Server Error");
      }
      const birthdays = users.map(user => {
        const { id, firstname, birthday } = user;
        return { id, name: firstname, bday: birthday };
      });
      res.json(birthdays);
    }
  );
});

// Get all users
app.get("/users", isAuthenticated, isAdmin, (req, res) => {
  db.all(
    "SELECT id, email, firstname, lastname, birthday, birthdayOptIn, isadmin FROM users",
    (err, users) => {
      if (err) {
        console.error("Error fetching users:", err);
        return res.status(500).send("Internal Server Error");
      }
      res.json(users);
    }
  );
});

// POST /users - Add a new user
app.post("/users", isAuthenticated, isAdmin, async (req, res) => {
  const { email, firstname, lastname, birthday, birthdayOptIn, isadmin, password } = req.body;

  if (!email || !firstname || !lastname || !password) {
    return res.status(400).send("Missing required fields");
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const stmt = db.prepare(`
      INSERT INTO users (email, firstname, lastname, birthday, birthdayOptIn, isadmin, password)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      [email, firstname, lastname, birthday, birthdayOptIn ? 1 : 0, isadmin ? 1 : 0, hashedPassword],
      function (err) {
        if (err) {
          console.error("Error adding new user:", err);
          return res.status(500).send("Error adding new user");
        }
        res.status(201).json({ id: this.lastID, message: "User added successfully" });
      }
    );

    stmt.finalize();
  } catch (error) {
    console.error("Error hashing password:", error);
    res.status(500).send("Internal Server Error");
  }
});

// PUT /users/:id - Update an existing user
app.put("/users/:id", isAuthenticated, isAdmin, async (req, res) => {
  const userId = req.params.id;
  const { email, firstname, lastname, birthday, birthdayOptIn, isadmin, password } = req.body;

  if (!email || !firstname || !lastname) {
    return res.status(400).send("Missing required fields");
  }

  try {
    let updateFields = [email, firstname, lastname, birthday, birthdayOptIn ? 1 : 0, isadmin ? 1 : 0];
    let sql = `
      UPDATE users 
      SET email = ?, firstname = ?, lastname = ?, birthday = ?, birthdayOptIn = ?, isadmin = ?
    `;

    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      updateFields.push(hashedPassword);
      sql += `, password = ?`;
    }

    sql += ` WHERE id = ?`;
    updateFields.push(userId);

    db.run(sql, updateFields, function (err) {
      if (err) {
        console.error("Error updating user:", err);
        return res.status(500).send("Error updating user");
      }
      if (this.changes === 0) {
        return res.status(404).send("User not found");
      }
      res.json({ message: "User updated successfully" });
    });
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).send("Internal Server Error");
  }
});

// DELETE /users/:id - Delete a user
app.delete("/users/:id", isAuthenticated, isAdmin, (req, res) => {
  const userId = req.params.id;

  db.run("DELETE FROM users WHERE id = ?", userId, function (err) {
    if (err) {
      console.error("Error deleting user:", err);
      return res.status(500).send("Error deleting user");
    }
    if (this.changes === 0) {
      return res.status(404).send("User not found");
    }
    res.json({ message: "User deleted successfully" });
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).render("404");
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});

// Close the database connection when the server is shut down
process.on("SIGINT", () => {
  db.close((err) => {
    if (err) {
      console.error(err.message);
    }
    console.log("Closed the database connection.");
    process.exit(0);
  });
});