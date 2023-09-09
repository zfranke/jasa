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


