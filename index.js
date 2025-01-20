const express = require('express'); 
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
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
    banned: { type: Boolean, default: false },
    role: { type: String, default: 'user' }, // New field for user role
    loginAttempts: { type: Number, default: 0 }, // Track failed login attempts
    lastAttempt: { type: Date } // Track the last login attempt time
});

const questionSchema = new mongoose.Schema({
    question: { type: String, required: true },
    options: { 
        a: { type: String, required: true },
        b: { type: String, required: true },
        c: { type: String, required: true },
        d: { type: String, required: true }
    },
    correctAnswer: { type: String, required: true } // Should be 'a', 'b', 'c', or 'd'
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

// Admin Authorization Middleware
const authorizeAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).send({ error: 'Access denied. Admins only.' });
    }
    next();
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

// User registration route
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
        const hashedPassword = await bcrypt.hash(password, 12);

        // Create new user
        const newUser  = new User({ username, password: hashedPassword, role: 'user' });
        await newUser .save();

        res.status(201).send('User  registered successfully');
    } catch (error) {
        res.status(400).send('Error registering user');
    }
});

// User login route
app.post('/api/users/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send({ error: 'Username and password are required' });
    }

    try {
        const user = await User.findOne({ username });

        // Check if user exists
        if (!user) {
            return res.status(401).send({ error: 'Invalid credentials' });
        }

        // Check if the user is locked out
        const now = new Date();
        if (user.loginAttempts >= 3) {
            const waitTime = 5 * 60 * 1000; // 5 minutes in milliseconds
            if (now - user.lastAttempt < waitTime) {
                return res.status(403).send({ error: 'Too many failed attempts. Please wait 5 minutes.' });
            } else {
                // Reset attempts after waiting period
                user.loginAttempts = 0;
            }
        }

        // Check password
        if (!(await bcrypt.compare(password, user.password))) {
            user.loginAttempts += 1; // Increment login attempts
            user.lastAttempt = now; // Update last attempt time
            await user.save(); // Save user data
            return res.status(401).send({ error: 'Invalid credentials' });
        }

        // Successful login
        user.loginAttempts = 0; // Reset attempts on successful login
        user.lastAttempt = null; // Clear last attempt time
        await user.save(); // Save user data

        const token = jwt.sign({ username: user.username, role: user.role }, jwtSecret, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).send({ error: 'An error occurred during login' });
    }
});

// User details route (GET)
app.get('/api/users/:username', authenticateToken, authorizeAdmin, async (req, res) => {
    const { username } = req.params;

    try {
        const user = await User.findOne({ username }, { password: 0 }); // Exclude password
        if (!user) {
            return res.status(404).send({ error: 'User  not found' });
        }
        res.send(user);
    } catch (error) {
        res.status(500).send({ error: 'An error occurred while fetching user details' });
    }
});

// User update and delete routes
app.patch('/api/users/:username', authenticateToken, authorizeAdmin, async (req, res) => {
    const { username } = req.params;
    const updates = req.body;

    try {
        const result = await User.updateOne({ username }, { $set: updates });
        if (result.nModified === 0) {
            return res.status(404).send({ error: 'User  not found' });
        }
        res.send({ message: 'User  updated successfully' });
    } catch (error) {
        res.status(500).send({ error: 'An error occurred while updating the user' });
    }
});

app.delete('/api/users/:username', authenticateToken, authorizeAdmin, async (req, res) => {
    const { username } = req.params;

    try {
        const result = await User.deleteOne({ username });
        if (result.deletedCount === 0) {
            return res.status(404).send({ error: 'User  not found' });
        }
        res.send({ message: 'User  deleted successfully' });
    } catch (error) {
        res.status(500).send({ error: 'An error occurred while deleting the user' });
    }
});

// Score routes
app.post('/api/scores', authenticateToken, async (req, res) => {
    const { username, score } = req.body;

    try {
        const newScore = new Score({ username, score });
        await newScore.save();
        res.status(201).send({ scoreId: newScore._id });
    } catch (error) {
        res.status(500).send({ error: 'An error occurred while saving the score' });
    }
});

// Admin route to get all players' scores
app.get('/api/admin/scores', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const scores = await Score.find(); // Fetch all scores from the database
        res.status(200).json(scores); // Send the score data as a response
    } catch (error) {
        res.status(500).json({ message: 'Error retrieving scores' });
    }
});

// Player route to get their own score
app.get('/api/scores/me', authenticateToken, async (req, res) => {
    const username = req.user.username; // Get the username from the token

    try {
        const score = await Score.findOne({ username });
        if (!score) {
            return res.status(404).send({ error: 'Score not found' });
        }
        res.send(score);
    } catch (error) {
        res.status(500).send({ error: 'An error occurred while fetching the score' });
    }
});

// Update and delete score routes for admin
app.patch('/api/scores/:username', authenticateToken, authorizeAdmin, async (req, res) => {
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

app.delete('/api/scores/:username', authenticateToken, authorizeAdmin, async (req, res) => {
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

// Question routes
app.post('/api/questions', authenticateToken, authorizeAdmin, async (req, res) => {
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

app.patch('/api/questions/:id', authenticateToken, authorizeAdmin, async (req, res) => {
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

app.delete('/api/questions/:id', authenticateToken, authorizeAdmin, async (req, res) => {
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

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('An error occurred:', err);
    res.status(500).send({ error: 'Internal Server Error' });
});