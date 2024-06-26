const express = require("express");
const path = require("path");
const session = require("express-session");
const authRoutes = require('./src/server/routes/auth');
const userRoutes = require('./src/server/routes/users');
const pageRoutes = require('./src/server/routes/pages');
const profileBirthdayRoutes = require('./src/server/routes/profileBirthday');
const errorHandler = require('./src/server/middleware/errorHandling');
const expressLayouts = require('express-ejs-layouts');


const app = express();
const port = process.env.PORT || 3000;

// Layout setup
app.use(expressLayouts);
app.set('layout', 'layouts/main');
app.set('layout extractScripts', true);
app.set('layout extractStyles', true);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "src", "public")));

// Session configuration
let sessionSecret;
const sessionSecretString = process.env.SESSION_SECRET;

if (sessionSecretString) {
  try {
    const jsonString = sessionSecretString.replace(/'/g, '"');
    sessionSecret = JSON.parse(jsonString);
    if (!Array.isArray(sessionSecret)) {
      throw new Error("Parsed result is not an array");
    }
  } catch (error) {
    console.error("Error parsing SESSION_SECRET:", error);
  }
}

app.use(session({
  secret: sessionSecret || "your_secret_key",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: app.get("env") === "production",
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// View engine setup
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "src", "views"));

// Routes
app.use('/', authRoutes);
app.use('/users', userRoutes);
app.use('/', pageRoutes);
app.use('/', profileBirthdayRoutes);

// 404 handler
app.use((req, res, next) => {
  res.status(404).render("pages/404");
});

// Error handling
app.use(errorHandler);

// Start server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});

// Graceful shutdown
process.on("SIGINT", async () => {
  console.log("Shutting down gracefully...");
  process.exit(0);
});