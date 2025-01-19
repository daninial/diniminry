const express = require('express'); 
const bodyParser = require('body-parser');
var cors = require('cors');
var jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const helmet = require('helmet');  
const rateLimit = require('express-rate-limit'); 
require('dotenv').config();  

const app = express();
const port = process.env.PORT || 3000;
const uri = process.env.MONGODB_URI;
const jwtSecret = process.env.JWT_SECRET;

app.use(helmet());  
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
    process.exit(1);  
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

// Store for tracking login attempts
const loginAttempts = {};

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

// Password validation function
const validatePassword = (password) => {
    const hasUpperCase = /[A-Z]/.test(password);
    const hasSymbol = /[!@#$%^&*]/.test(password);
    const isValidLength = password.length >= 6;

    if (!isValidLength) {
        return 'Password must be at least 6 characters long.';
    }
    if (!hasUpperCase) {
        return 'Password must contain at least one uppercase letter.';
    }
    if (!hasSymbol) {
        return 'Password must contain at least one symbol.';
    }
    return null; // Password is valid
};

// Rate limiting middleware
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});

// Apply rate limiting to specific routes
app.use('/api/users/register', limiter);
app.use('/api/users/login', limiter);

// User routes
app.post('/api/users/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send({ error: 'Username and password are required' });
    }

    const passwordError = validatePassword(password);
    if (passwordError) {
        return res.status(400).send({ error: passwordError });
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

    // Check if the user is locked out
    const attempts = loginAttempts[username] || { count: 0, lastAttempt: null };
    const lockoutTime = 5 * 60 * 1000; // 5 minutes

    if (attempts.count >= 2 && attempts.lastAttempt && (Date.now() - attempts.lastAttempt < lockoutTime)) {
        return res.status(403).send({ error: 'Too many failed login attempts. Please try again later.' });
    }

    try {
        const user = await User.findOne({ username });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            // Increment the failed login attempt count
            attempts.count += 1;
            attempts.lastAttempt = Date.now();
            loginAttempts[username] = attempts;

            return res.status(401).send({ error: 'Invalid credentials' });
        }

        // Reset the attempts on successful login
        loginAttempts[username] = { count: 0, lastAttempt: null };

        const token = jwt.sign({ username: user.username }, jwtSecret, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).send({ error: 'An error occurred during login' });
    }
});

// Question routes
app.post('/api/questions', authenticateToken, async (req, res) => {
    const { question, options, correctAnswer } = req.body;

    try {
        const newQuestion = new Question({ question, options, correctAnswer });
        const result = await newQuestion.save();
        res.status(201).send({ questionId: result._id });
    } catch (error) {
        res.status(500).send({ error: 'An error occurred while creating the question' });
    }
});

app.get('/api/questions', authenticateToken, async (req, res) => {
    try {
        const questions = await Question.find({}, { correctAnswer: 0, _id: 0 }).lean();
        res.send(questions);
    } catch (error) {
        res.status(500).send({ error: 'An error occurred while fetching the questions' });
    }
});

app.patch('/api/questions/:id', authenticateToken, async (req, res) => {
    const questionId = req.params.id;
    const { question, options, correctAnswer } = req.body;

    try {
        const result = await Question.updateOne(
            { _id: questionId },
            { $set: { question, options, correctAnswer } }
        );

        if (result.nModified === 0) {
            return res.status(404).send({ error: 'Question not found' });
        }

        res.send({ message: 'Question updated successfully' });
    } catch (error) {
        res.status(500).send({ error: 'An error occurred while updating the question' });
    }
});

app.delete('/api/questions/:id', authenticateToken, async (req, res) => {
    const questionId = req.params.id;

    try {
        const result = await Question.deleteOne({ _id: questionId });

        if (result.deletedCount === 0) {
            return res.status(404).send({ error: 'Question not found' });
        }

        res.send({ message: 'Question deleted successfully' });
    } catch (error) {
        res.status(500).send({ error: 'An error occurred while deleting the question' });
    }
});

// Score routes
app.post('/api/scores', authenticateToken, async (req, res) => {
    const { username, score } = req.body;

    try {
        const newScore = new Score({ username, score });
        const result = await newScore.save();
        res.status(201).send({ scoreId: result._id });
    } catch (error) {
        res.status(500).send({ error: 'An error occurred while saving the score' });
    }
});

app.get('/api/scores', authenticateToken, async (req, res) => {
    try {
        const scores = await Score.find({}, { _id: 0 }).lean();
        res.send(scores);
    } catch (error) {
        res.status(500).send({ error: 'An error occurred while fetching the scores' });
    }
});

app.patch('/api/scores/:username', authenticateToken, async (req, res) => {
    const username = req.params.username;
    const { score } = req.body;

    try {
        const result = await Score.updateOne({ username }, { $set: { score } });
        if (result.nModified === 0) {
            return res.status(404).send({ error: 'Score not found' });
        }
        res.send({ message: 'Score updated successfully' });
    } catch (error) {
        res.status(500).send({ error: 'An error occurred while updating the score' });
    }
});

app.delete('/api/scores/:username', authenticateToken, async (req, res) => {
    const username = req.params.username;

    try {
        const result = await Score.deleteOne({ username });

        if (result.deletedCount === 0) {
            return res.status(404).send({ error: 'Score not found' });
        }

        res.send({ message: 'Score deleted successfully' });
    } catch (error) {
        res.status(500).send({ error: 'An error occurred while deleting the score' });
    }
});

// Submit answers route
app.post('/api/submit', authenticateToken, async (req, res) => {
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

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('An error occurred:', err);
    res.status(500).send({ error: 'Internal Server Error' });
});