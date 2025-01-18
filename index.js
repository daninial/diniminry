const express = require('express');
const bodyParser = require('body-parser');
var cors = require('cors');
var jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');
require('dotenv').config();  // Load environment variables from .env file

const app = express();
const port = process.env.PORT || 3000;
const uri = process.env.MONGODB_URI;
const jwtSecret = process.env.JWT_SECRET;

app.use(cors());
app.use(bodyParser.json());

// Connect to MongoDB using mongoose
mongoose.connect(uri, {
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
}).then(() => {
    console.log('Connected to MongoDB');
    
    // Start the server
    app.listen(port, () => {
        console.log(`Server running on port ${port}`);
    });
}).catch(err => {
    console.error('Failed to connect to MongoDB:', err);
    process.exit(1);  // Exit process on failure to connect to MongoDB
});

// Define Schemas and Models
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
});

const questionSchema = new mongoose.Schema({
    question: { type: String, required: true },
    options: { type: [String], required: true },
    correctAnswer: { type: String, required: true },
});

const scoreSchema = new mongoose.Schema({
    username: { type: String, required: true },
    score: { type: Number, required: true },
    date: { type: Date, default: Date.now },
});

const User = mongoose.model('User ', userSchema);
const Question = mongoose.model('Question', questionSchema);
const Score = mongoose.model('Score', scoreSchema);

// Middleware for authentication
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Rate limiter middleware
const limiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 1, // Limit each user to 1 request per windowMs
    message: 'Too many requests, please try again later.',
    keyGenerator: (req, res) => {
        return req.user.username; // Use the username as the key for rate limiting
    },
});

// Apply the rate limiter to the submit route
app.post('/api/submit', authenticateToken, limiter, async (req, res) => {
    const { username, answers } = req.body;

    try {
        // Fetch all questions
        const questions = await Question.find({}).lean();

        if (questions.length !== answers.length) {
            return res.status(400).send('Number of answers does not match number of questions');
        }

        // Calculate score
        let score = 0;
        for (let i = 0; i < questions.length; i++) {
            if (questions[i].correctAnswer === answers[i]) {
                score++;
            }
        }

        // Save score to the database
        const newScore = new Score({ username, score });
        await newScore.save();

        res.status(201).send({ message: 'Score submitted successfully', score });
    } catch (error) {
        res.status(500).send({ error: 'An error occurred while submitting the answers' });
    }
});

// User routes
app.post('/api/users/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send({ error: 'Username and password are required' });
    }

    try {
        // Check if user already exists
        const existingUser  = await User.findOne({ username });
        if (existingUser ) {
            return res.status(400).send({ error: 'User  already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        const newUser  = new User({ username, password: hashedPassword });
        await newUser .save();

        res.status(201).send('User  registered successfully');
    } catch (error) {
        res.status(400).send('Error registering user');
    }
});

app.post('/api/users/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send({ error: 'Username and password are required' });
    }

    try {
        const user = await User.findOne({ username });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).send({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ username: user.username }, jwtSecret, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).send({ error: 'An error occurred during login' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('An error occurred:', err);
    res.status(500).send({ error: 'Internal Server Error' });
});
