const express = require('express')
const app = express()
const port = process.env.PORT || 3000
const bcrypt = require('bcrypt')
app.use(express.json())

app.post('/user', async (req, res) => {
    //console.log(req.body);
    //insertOne
  
    const hash = bcrypt.hashSync(req.body.password, 10);
  
    let result = await client.db ('Zulll').collection('Data').insertOne(
      {
        username: req.body.username,
        password: hash,
        name: req.body.name,
        email: req.body.email,
      }
    )
    
    res.send(result);
  })

app.post('/login', async (req, res) => {
    //username: req.body.username,
    //password: req.body.password,
  
    //Step 1. Check if the username exist in the database
    let result = await client.db ('Zulll').collection('Data').findOne(
      {
      username: req.body.username,
    }
  )
  
  if (!result) res.send('Invalid username');
  else {
    //step 2: Check if the password is correct
    if (bcrypt.compareSync(req.body.password, result.password)) {
      res.send('Login successful');
    } else {
      res.send('Invalid password');
    }
  }
  })

app.get('/user/:username/:email', async (req, res) => {
  let result = await client.db('Zulll').collection('Data').findOne({
    username: req.params.username,
    email: req.params.email
  })
  res.send(result)
})

app.patch('/user/:id', async (req, res) => {
    //updateOne
    //console.log('User profile updated')
    let result = await client.db ('Zulll').collection('Data').updateOne(
      {
        _id: new ObjectId (req.params.id),
      },
      {
        $set: {
          name: req.body.name,
        }
      }
    );
    res.send(result);
  })

app.delete('/user/:id', async (req, res) => {
  let result = await client.db("Zulll").collection("Data").deleteOne({
    _id: new ObjectId(req.params.id)
  })
  res.send(result)
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})

const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const uri = "mongodb+srv://b022210198:030201@clusterberr2423.5imns99.mongodb.net/?retryWrites=true&w=majority&appName=ClusterBERR2423";

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    await client.connect()
    console.log('Connected successfully to MongoDB')
  } finally {
  }
}
run().catch(console.dir)