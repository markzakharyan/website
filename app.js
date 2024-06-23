const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const cookieParser = require("cookie-parser");

const app = express();
const port = 3000;

app.use(cookieParser());

app.use(express.json());
app.use(express.static("public"));

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
function authenticateToken(req, res, next) {
  const token = req.cookies.token;

  jwt.verify(token, "your_secret_key", (err, user) => {
    req.user = user;
    next();
  });
}

// Serve home page
app.get("/", authenticateToken, (req, res) => {
  if (req.user) {
    db.get(
      "SELECT * FROM users WHERE id = ?",
      [req.user.userId],
      (err, user) => {
        if (err) {
          console.error("Error fetching user:", err);
          return res.status(500).send("Internal Server Error");
        }
        if (user) {
          if (user.isadmin) {
            res.render("index_loggedin_admin", { user: user });
          }
          res.render("index_loggedin", { user: user });
        } else {
          res.clearCookie("token");
          res.render("index");
        }
      }
    );
  } else {
    res.render("index");
  }
});

app.get("/roxy", (req, res) => {
  res.render("roxy");
});

app.get("/fourier", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "fourier.html"));
});

app.get("/manage_users", authenticateToken, isAdmin, (req, res) => {
  res.render("manage_users");
});

// User registration
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [name, email, hashedPassword],
      function (err) {
        if (err) {
          return res.status(400).json({ error: "Email already exists" });
        }
        res.status(201).json({ message: "User registered successfully" });
      }
    );
  } catch (error) {
    res.status(500).json({ error: "Error registering user" });
  }
});

// User login
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  console.log("Login attempt:", email);

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (err) {
      console.error("Database error:", err);
      return res
        .status(500)
        .json({ success: false, error: "Error accessing database" });
    }
    if (!user) {
      console.log("User not found:", email);
      return res
        .status(400)
        .json({ success: false, error: "Invalid credentials" });
    }
    try {
      const isMatch = await bcrypt.compare(password, user.password);
      console.log("Password match:", isMatch);
      if (isMatch) {
        const token = jwt.sign({ userId: user.id }, "your_secret_key", {
          expiresIn: "1h",
        });
        res.cookie("token", token, { httpOnly: true, maxAge: 3600000 }); // 1 hour
        console.log("Login successful:", email);
        return res.json({ success: true, user: user });
      } else {
        console.log("Password mismatch:", email);
        return res
          .status(400)
          .json({ success: false, error: "Invalid credentials" });
      }
    } catch (error) {
      console.error("Login error:", error);
      return res
        .status(500)
        .json({ success: false, error: "Error logging in" });
    }
  });
});

// Logout
app.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ success: true });
});

// Get all users
app.get("/users", authenticateToken, isAdmin, (req, res) => {
  if (!req.user) {
    return res.status(401).send("Unauthorized");
  }

  db.get(
    "SELECT * FROM users WHERE id = ?",
    [req.user.userId],
    async (err, user) => {
      if (err) {
        console.error("Error fetching user:", err);
        return res.status(500).send("Internal Server Error");
      }
      if (!user) {
        return res.status(404).send("User not found");
      }

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
    }
  );
});

app.use(express.json());

// Middleware to check if user is admin
function isAdmin(req, res, next) {
  if (!req.user || !req.user.userId) {
    return res.status(401).send("Unauthorized");
  }

  db.get(
    "SELECT isadmin FROM users WHERE id = ?",
    [req.user.userId],
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

// POST /users - Add a new user
app.post("/users", authenticateToken, isAdmin, async (req, res) => {
  const {
    email,
    firstname,
    lastname,
    birthday,
    birthdayOptIn,
    isadmin,
    password,
  } = req.body;

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
      [
        email,
        firstname,
        lastname,
        birthday,
        birthdayOptIn ? 1 : 0,
        isadmin ? 1 : 0,
        hashedPassword,
      ],
      function (err) {
        if (err) {
          console.error("Error adding new user:", err);
          return res.status(500).send("Error adding new user");
        }
        res
          .status(201)
          .json({ id: this.lastID, message: "User added successfully" });
      }
    );

    stmt.finalize();
  } catch (error) {
    console.error("Error hashing password:", error);
    res.status(500).send("Internal Server Error");
  }
});

// PUT /users/:id - Update an existing user
app.put("/users/:id", authenticateToken, isAdmin, async (req, res) => {
  const userId = req.params.id;
  const {
    email,
    firstname,
    lastname,
    birthday,
    birthdayOptIn,
    isadmin,
    password,
  } = req.body;

  if (!email || !firstname || !lastname) {
    return res.status(400).send("Missing required fields");
  }

  try {
    let updateFields = [
      email,
      firstname,
      lastname,
      birthday,
      birthdayOptIn ? 1 : 0,
      isadmin ? 1 : 0,
    ];
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
app.delete("/users/:id", authenticateToken, isAdmin, (req, res) => {
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
