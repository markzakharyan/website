const express = require("express");
const bcrypt = require("bcrypt");
const path = require("path");
const { Pool } = require("pg");
const session = require("express-session");

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

let sessionSecret;
const sessionSecretString = process.env.SESSION_SECRET;

if (sessionSecretString) {
  try {
    // Remove the single quotes around the array elements and replace them with double quotes
    const jsonString = sessionSecretString.replace(/'/g, '"');

    // Parse the JSON string into an array
    sessionSecret = JSON.parse(jsonString);

    // Validate that we got an array
    if (!Array.isArray(sessionSecret)) {
      throw new Error("Parsed result is not an array");
    }
  } catch (error) {
    console.error("Error parsing SESSION_SECRET:", error);
    // Fallback to using the string as-is if parsing fails
  }
}


var sess = {
  secret: sessionSecret || "your_secret_key",
  resave: false,
  saveUninitialized: false,
  cookie: {},
};

if (app.get("env") === "production") {
  app.set("trust proxy", 1); // trust first proxy
  sess.cookie.secure = true; // serve secure cookies
}

// Set up session middleware
app.use(session(sess));

// Set EJS as the view engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Set up the database connection pool
console.log("database running at " + (app.get("env") === "production" ? process.env.DATABASE_PRIVATE_URL : process.env.DATABASE_URL));
const pool = new Pool({
  connectionString: app.get("env") === "production" ? process.env.DATABASE_PRIVATE_URL : process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false,
});

// Initialize the database
async function initializeDatabase() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE,
        firstname TEXT,
        lastname TEXT,
        birthday TEXT,
        birthdayOptIn BOOLEAN,
        isadmin BOOLEAN,
        password TEXT
      )
    `);
    console.log("Users table ready");
  } catch (err) {
    console.error("Error creating users table", err);
  } finally {
    client.release();
  }
}

initializeDatabase();

// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
  if (req.session.userId) {
    next();
  } else {
    res.status(401).send("Unauthorized");
  }
}

// Middleware to check if user is admin
async function isAdmin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).send("Unauthorized");
  }

  try {
    const result = await pool.query("SELECT isadmin FROM users WHERE id = $1", [
      req.session.userId,
    ]);
    if (result.rows.length === 0) {
      return res.status(404).send("User not found");
    }
    if (!result.rows[0].isadmin) {
      return res.status(403).send("Forbidden: Admin access required");
    }
    next();
  } catch (err) {
    console.error("Database error:", err);
    return res.status(500).send("Internal Server Error");
  }
}

// Serve home page
app.get("/", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM users WHERE id = $1", [
      req.session.userId,
    ]);
    const user = result.rows[0];
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
        res.render("index");
      });
    }
  } catch (err) {
    console.error("Error fetching user:", err);
    return res.status(500).send("Internal Server Error");
  }
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

// Route to render the manage user page
app.get("/manage-profile", isAuthenticated, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM users WHERE id = $1", [
      req.session.userId,
    ]);
    const user = result.rows[0];
    res.render("manage_user", { user });
  } catch (error) {
    console.error("Error fetching user data:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Route to handle profile updates
app.post("/update-profile", isAuthenticated, async (req, res) => {
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

// GET route to display the registration form
app.get("/register", (req, res) => {
  res.render("register");
});

// POST route to handle form submission
app.post("/register", async (req, res) => {
  const {
    email,
    firstname,
    lastname,
    password,
    confirm_password,
    birthday,
    birthdayOptIn,
  } = req.body;

  if (!email || !firstname || !lastname || !password || !confirm_password) {
    return res.render("register", {
      error: "All required fields must be filled",
    });
  }

  if (password !== confirm_password) {
    return res.render("register", { error: "Passwords do not match" });
  }

  try {
    const userCheck = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (userCheck.rows.length > 0) {
      return res.render("register", { error: "Email already in use" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `
      INSERT INTO users (email, firstname, lastname, password, birthday, birthdayOptIn, isadmin)
      VALUES ($1, $2, $3, $4, $5, $6, false) RETURNING id
    `,
      [
        email,
        firstname,
        lastname,
        hashedPassword,
        birthday || null,
        birthdayOptIn,
      ]
    );

    req.session.userId = result.rows[0].id;
    req.session.email = email;
    res.redirect("/");
  } catch (error) {
    console.error("Error in registration process:", error);
    res.render("register", { error: "An error occurred during registration" });
  }
});

// User login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  console.log("Login attempt:", email);

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (result.rows.length === 0) {
      console.log("User not found:", email);
      return res
        .status(400)
        .json({ success: false, error: "Invalid credentials" });
    }

    const user = result.rows[0];

    const isMatch = await bcrypt.compare(password, user.password);
    console.log("Password match:", isMatch);

    if (isMatch) {
      req.session.userId = user.id;
      req.session.email = user.email;
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
    return res.status(500).json({ success: false, error: "Error logging in" });
  }
});

// Logout
app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
      return res
        .status(500)
        .json({ success: false, error: "Error logging out" });
    }
    res.json({ success: true });
  });
});

// GET /birthdays - Get all users who have opted in to share their birthday
app.get("/get_birthdays", async (req, res) => {
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
    res.status(500).send("Internal Server Error");
  }
});

// Get all users
app.get("/users", isAuthenticated, isAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, email, firstname, lastname, birthday, birthdayOptIn, isadmin FROM users"
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).send("Internal Server Error");
  }
});

// POST /users - Add a new user
app.post("/users", isAuthenticated, isAdmin, async (req, res) => {
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
    const result = await pool.query(
      `
      INSERT INTO users (email, firstname, lastname, birthday, birthdayOptIn, isadmin, password)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING id
    `,
      [
        email,
        firstname,
        lastname,
        birthday,
        birthdayOptIn,
        isadmin,
        hashedPassword,
      ]
    );

    res.status(201).json({
      id: result.rows[0].id,
      message: "User added successfully",
    });
  } catch (error) {
    console.error("Error adding new user:", error);
    res.status(500).send("Error adding new user");
  }
});

// PUT /users/:id - Update an existing user
app.put("/users/:id", isAuthenticated, isAdmin, async (req, res) => {
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
      birthdayOptIn,
      isadmin,
      userId,
    ];
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
      return res.status(404).send("User not found");
    }
    res.json({ message: "User updated successfully" });
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).send("Error updating user");
  }
});

// DELETE /users/:id - Delete a user
app.delete("/users/:id", isAuthenticated, isAdmin, async (req, res) => {
  const userId = req.params.id;

  try {
    const result = await pool.query("DELETE FROM users WHERE id = $1", [
      userId,
    ]);
    if (result.rowCount === 0) {
      return res.status(404).send("User not found");
    }
    res.json({ message: "User deleted successfully" });
  } catch (err) {
    console.error("Error deleting user:", err);
    res.status(500).send("Error deleting user");
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).render("404");
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});

// Graceful shutdown
process.on("SIGINT", async () => {
  try {
    await pool.end();
    console.log("Closed the database connection.");
    process.exit(0);
  } catch (err) {
    console.error("Error closing database connection:", err);
    process.exit(1);
  }
});
