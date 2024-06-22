const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const cookieParser = require('cookie-parser');

const app = express();
const port = 3000;

app.use(cookieParser());

app.use(express.json());
app.use(express.static('public'));

// Set EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Set up the database
const db = new sqlite3.Database('./users.db', (err) => {
  if (err) {
    console.error('Error opening database', err);
  } else {
    console.log('Connected to the SQLite database.');
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE,
      name TEXT,
      password TEXT
    )`, (err) => {
      if (err) {
        console.error('Error creating users table', err);
      } else {
        console.log('Users table ready');
      }
    });
  }
});

// Middleware to check if user is authenticated
function authenticateToken(req, res, next) {
  const token = req.cookies.token;

  jwt.verify(token, 'your_secret_key', (err, user) => {
    req.user = user;
    next();
  });
}

// Serve home page
app.get('/', authenticateToken, (req, res) => {
  if (req.user) {
    db.get('SELECT * FROM users WHERE id = ?', [req.user.userId], (err, user) => {
      if (err) {
        console.error('Error fetching user:', err);
        return res.status(500).send('Internal Server Error');
      }
      if (user) {
        res.render('index_loggedin', { user: user });
      } else {
        res.clearCookie('token');
        res.render('index');
      }
    });
  } else {
    res.render('index');
  }
});


app.get('/fourier', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'fourier.html'));
});

app.get('/roxy', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'roxy.html'));
});

app.get('/adduser', (req, res) => {
  res.sendFile(path.join(__dirname, 'adduser.html'));
});


// User registration
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, email, hashedPassword], function(err) {
      if (err) {
        return res.status(400).json({ error: 'Email already exists' });
      }
      res.status(201).json({ message: 'User registered successfully' });
    });
  } catch (error) {
    res.status(500).json({ error: 'Error registering user' });
  }
});

// User login
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  console.log('Login attempt:', email);

  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, error: 'Error accessing database' });
    }
    if (!user) {
      console.log('User not found:', email);
      return res.status(400).json({ success: false, error: 'Invalid credentials' });
    }
    try {
      const isMatch = await bcrypt.compare(password, user.password);
      console.log('Password match:', isMatch);
      if (isMatch) {
        const token = jwt.sign({ userId: user.id }, 'your_secret_key', { expiresIn: '1h' });
        res.cookie('token', token, { httpOnly: true, maxAge: 3600000 }); // 1 hour
        console.log('Login successful:', email);
        return res.json({ success: true, user: user });
      } else {
        console.log('Password mismatch:', email);
        return res.status(400).json({ success: false, error: 'Invalid credentials' });
      }
    } catch (error) {
      console.error('Login error:', error);
      return res.status(500).json({ success: false, error: 'Error logging in' });
    }
  });
});


// Logout
app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

// 404 handler
app.use((req, res) => {
  res.status(404).render('404');
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});

// Close the database connection when the server is shut down
process.on('SIGINT', () => {
  db.close((err) => {
    if (err) {
      console.error(err.message);
    }
    console.log('Closed the database connection.');
    process.exit(0);
  });
});