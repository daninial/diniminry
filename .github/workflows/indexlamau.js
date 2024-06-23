
const express = require('express');
const bodyParser = require('body-parser');
var cors = require('cors');
var jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');  // Ensure bcrypt is imported
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const app = express();
const port = process.env.PORT || 3000;
const uri = process.env.MONGODB_URI || "mongodb+srv://fauzan:lmaolmao@fauzan.1ml0u5f.mongodb.net/?retryWrites=true&w=majority&appName=fauzan";
const jwtSecret = process.env.JWT_SECRET || 'skillissue';

app.use(cors());
app.use(bodyParser.json());

// Connect to MongoDB 
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

client.connect().then(() => {
  console.log('Connected to MongoDB');
  const db = client.db('quiz_game');
  app.locals.db = db;

  // Start the server
  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
}).catch(err => {
  console.error('Failed to connect to MongoDB:', err);
  process.exit(1);  // Exit process on failure to connect to MongoDB
});

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

// User routes
app.post('/api/users/register', async (req, res) => {
  const db = req.app.locals.db;
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send({ error: 'Username and password are required' });
  }

  try {
    // Check if user already exists
    const existingUser = await db.collection('users').findOne({ username });
    if (existingUser) {
      return res.status(400).send({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = { username, password: hashedPassword };
    const result = await db.collection('users').insertOne(newUser);

    res.status(201).send('User registered successfully');
  } catch (error) {
    res.status(400).send('Error registering user');
  }
});

app.post('/api/users/login', async (req, res) => {
  const db = req.app.locals.db;
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send({ error: 'Username and password are required' });
  }

  try {
    const user = await db.collection('users').findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).send({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      console.error('Invalid password');
      return res.status(400).send({ error: 'Invalid username or password' });
    }

    const token = jwt.sign({ username: user.username }, jwtSecret, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).send({ error: 'An error occurred during login' });
  }
});

app.get('/api/users/:username', authenticateToken, async (req, res) => {
  const db = req.app.locals.db;
  const username = req.params.username;

  try {
    const user = await db.collection('users').findOne({ username });
    if (!user) {
      return res.status(404).send({ error: 'User not found' });
    }
    res.send(user);
  } catch (error) {
    console.error('Get User Error:', error);
    res.status(500).send({ error: 'An error occurred while fetching the user' });
  }
});

app.patch('/api/users/:username', authenticateToken, async (req, res) => {
  const db = req.app.locals.db;
  const { username } = req.params;
  const update = req.body;

  try {
    if (update.password) {
      update.password = await bcrypt.hash(update.password, 10);
    }
    const result = await db.collection('users').updateOne({ username }, { $set: update });
    res.status(201).send(result);
  } catch (error) {
    res.status(400).send({ error: error.message });
  }
});

app.delete('/api/users/:username', authenticateToken, async (req, res) => {
  const db = req.app.locals.db;
  const username = req.params.username;

  try {
    const result = await db.collection('users').deleteOne({ username });
    if (result.deletedCount === 0) {
      return res.status(404).send({ error: 'User not found' });
    }
    res.send({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Delete User Error:', error);
    res.status(500).send({ error: 'An error occurred while deleting the user' });
  }
});

// Question routes
app.post('/api/questions', authenticateToken, async (req, res) => {
  const db = req.app.locals.db;
  const { question, options, correctAnswer } = req.body;

  try {
    const result = await db.collection('question').insertOne({ question, options, correctAnswer });
    res.status(201).send({ questionId: result.insertedId });
  } catch (error) {
    console.error('Create Question Error:', error);
    res.status(500).send({ error: 'An error occurred while creating the question' });
  }
});

app.get('/api/questions', authenticateToken, async (req, res) => {
  const db = req.app.locals.db;

  try {
    const questions = await db.collection('question').find({}, { projection: { correctAnswer: 0, _id: 0 } }).toArray();
    res.send(questions);
  } catch (error) {
    console.error('Fetch Questions Error:', error);
    res.status(500).send({ error: 'An error occurred while fetching the questions' });
  }
});

app.patch('/api/questions/:id', authenticateToken, async (req, res) => {
  const db = req.app.locals.db;
  const questionId = req.params.id;
  const { question, options, correctAnswer } = req.body;

  try {
    const result = await db.collection('question').updateOne(
      { _id: ObjectId(questionId) },
      { $set: { question, options, correctAnswer } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).send({ error: 'Question not found' });
    }

    res.send({ message: 'Question updated successfully' });
  } catch (error) {
    console.error('Update Question Error:', error);
    res.status(500).send({ error: 'An error occurred while updating the question' });
  }
});

app.delete('/api/questions/:id', authenticateToken, async (req, res) => {
  const db = req.app.locals.db;
  const questionId = req.params.id;

  try {
    const result = await db.collection('question').deleteOne({ _id: ObjectId(questionId) });

    if (result.deletedCount === 0) {
      return res.status(404).send({ error: 'Question not found' });
    }

    res.send({ message: 'Question deleted successfully' });
  } catch (error) {
    console.error('Delete Question Error:', error);
    res.status(500).send({ error: 'An error occurred while deleting the question' });
  }
});

// Score routes
app.post('/api/scores', authenticateToken, async (req, res) => {
  const db = req.app.locals.db;
  const { username, score } = req.body;

  try {
    const result = await db.collection('scores').insertOne({ username, score });
    res.status(201).send({ scoreId: result.insertedId });
  } catch (error) {
    console.error('Save Score Error:', error);
    res.status(500).send({ error: 'An error occurred while saving the score' });
  }
});

app.get('/api/playerscores', authenticateToken, async (req, res) => {
  const db = req.app.locals.db;

  try {
    const scores = await db.collection('scores').find({}, { projection: { _id: 0 } }).toArray();
    res.send(scores);
  } catch (error) {
    console.error('Fetch Scores Error:', error);
    res.status(500).send({ error: 'An error occurred while fetching the scores' });
  }
});

app.patch('/api/scores/:username', authenticateToken, async (req, res) => {
  const db = req.app.locals.db;
  const username = req.params.username;
  const { score } = req.body;

  try {
    const result = await db.collection('scores').updateOne(
      { username },
      { $set: { score } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).send({ error: 'Score not found' });
    }

    res.send({ message: 'Score updated successfully' });
  } catch (error) {
    console.error('Update Score Error:', error);
    res.status(500).send({ error: 'An error occurred while updating the score' });
  }
});

app.delete('/api/scores/:username', authenticateToken, async (req, res) => {
  const db = req.app.locals.db;
  const username = req.params.username;

  try {
    const result = await db.collection('scores').deleteOne({ username});

    if (result.deletedCount === 0) {
      return res.status(404).send({ error: 'Score not found' });
    }

    res.send({ message: 'Score deleted successfully' });
  } catch (error) {
    console.error('Delete Score Error:', error);
    res.status(500).send({ error: 'An error occurred while deleting the score' });
  }
});

// Submit answers route
app.post('/api/submit', authenticateToken, async (req, res) => {
  const db = req.app.locals.db;
  const { username, answers } = req.body;

  try {
    // Fetch all questions
    const questions = await db.collection('question').find({}).toArray();

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
    const result = await db.collection('scores').insertOne({ username, score, date: new Date() });

    res.status(201).send({ message: 'Score submitted successfully', score });
  } catch (error) {
    console.error('Submit Answers Error:', error);
    res.status(500).send({ error: 'An error occurred while submitting the answers' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('An error occurred:', err);
  res.status(500).send({ error: 'Internal Server Error' });
});
