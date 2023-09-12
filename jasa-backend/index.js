const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 7001;

// Enable CORS with configured options
app.use(cors());
app.use(bodyParser.json());

// Create a connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  waitForConnections: true,
  connectionLimit: 10, // Adjust this based on your requirements
  queueLimit: 0,
});

// Ping database to check for common exception errors.
pool.getConnection((err, connection) => {
    if (err) throw err;
    console.log('JASA: Database connected');
    connection.release();
    }
);


//Auth functions
const generateAccessToken = (user) => {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1800s' });
}

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; //Bearer TOKEN
    if (token == null) return res.sendStatus(401);
  
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    });
}

const hashPassword = async (password) => {
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    return hash;
}

const comparePassword = async (password, hash) => {
    return await bcrypt.compare(password, hash);
}

//Routes

//Ping route
app.get('/', (req, res) => {
    res.send('JASA: API is running');
});

//Ping database route
app.get('/pingdb', (req, res) => {
    pool.query('SELECT 1 + 1 AS solution', (err, result) => {
        if (err) {
            console.log(err);
            res.status(500).send('JASA: Error pinging database');
        } else {
            res.status(200).json(result);
        }
    });
});


//Register route
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await hashPassword(password);
    const user = {
        username: username,
        password: hashedPassword
    }

    pool.query('INSERT INTO users SET ?', user, (err, result) => {
        if (err) {
            console.log(err);
            res.status(500).send('JASA: Error registering user');
        } else {
            res.status(200).send('JASA: User registered');
        }
    });
});

//Login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    pool.query('SELECT * FROM users WHERE username = ?', username, async (err, result) => {
        if (err) {
            console.log(err);
            res.status(500).send('JASA: Error logging in');
        } else {
            if (result.length > 0) {
                const user = result[0];
                const validPassword = await comparePassword(password, user.password);
                if (validPassword) {
                    const accessToken = generateAccessToken({ username: user.username });
                    res.status(200).json({ accessToken: accessToken });
                } else {
                    res.status(401).send('JASA: Incorrect password');
                }
            } else {
                res.status(404).send('JASA: User not found');
            }
        }
    });
});

//Get all users route
app.get('/users', authenticateToken, (req, res) => {
    pool.query('SELECT * FROM users', (err, result) => {
        if (err) {
            console.log(err);
            res.status(500).send('JASA: Error getting users');
        } else {
            res.status(200).json(result);
        }
    });
});

//Get results route
app.get('/results', authenticateToken, async (req, res) => {
  // Implement code to retrieve survey results here
  // You can filter by survey_id and date range as needed
    // You can also implement pagination if you want
    const { survey_id, start_date, end_date } = req.query;
    let query = 'SELECT * FROM results';
    let conditions = [];
    let values = [];

    if (survey_id) {
        conditions.push('survey_id = ?');
        values.push(survey_id);
    }

    if (start_date) {
        conditions.push('created_at >= ?');
        values.push(start_date);
    }

    if (end_date) {
        conditions.push('created_at <= ?');
        values.push(end_date);
    }

    if (conditions.length > 0) {
        query += ' WHERE ' + conditions.join(' AND ');
    }

    pool.query(query, values, (err, result) => {
        if (err) {
            console.log(err);
            res.status(500).send('JASA: Error getting results');
        } else {
            res.status(200).json(result);
        }
    }
    );
});

//Post a result route (no auth)
app.post('/results', async (req, res) => {
  const { survey_id, choice } = req.body;

  try {
    await pool.query('INSERT INTO results (survey_id, choice) VALUES (?, ?)', [
      survey_id,
      choice,
    ]);
    res.status(201).json({ message: 'Survey result submitted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

//Start server
app.listen(port, () => {
    console.log(`JASA: Server listening on port ${port}`);
});



