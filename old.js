// const express = require('express')
// const app = express()
// const port = process.env.PORT || 3000;
// const bcrypt = require('bcrypt');
// const saltRounds = 10;

// app.use(express.json())
// // `
// // app.get('/inc' , async (req,res) => {
// //   client.db("maybank2u").collection("items").updateOne(
// //     {name: { $eq: "Nasi Lemak"}},
// //     {
// //       $inc: { price:3}
// //     }
// //   )
// //   res.send(result)
// // })`

// app.post('/register', async (req, res) => {

//   if (req.body.username != null && req.body.password != null) {
    
//     let findSimilar = await client.db("acc").collection("account").findOne(
//       {
//         username: req.body.username
//       }
//     )

//     if (!findSimilar) {

//       const hash = bcrypt.hashSync(req.body.password, saltRounds)

//       let result = await client.db("acc").collection("account").insertOne(
//         {
//           username: req.body.username,
//           password: hash
//         }
//       )

//       if (result) {
//         res.send(`Successfully registered!`)
//         console.log(`Inserted into DB\nusername: ${req.body.username}\npassword: ${req.body.password}`)
//       } else {
//         res. send(`Something went wrong! Please try again.`)
//       }

//     } else {
//       res.send(`The username ${req.body.username} is already taken.`)    
//     }

//   } else {
//     res.send(`Please enter a username and password.`)
//   }

// })

// app.get(`/login`, async (req, res) => {

//   let result = await client.db("acc").collection("account").findOne(
//     {
//       username: req.body.username
//     }
//   )

//   if (result) {
//     if(bcrypt.compareSync(req.body.password, result.password) == true) {
//       res.send(`Successfully login for ${result.username}`)
//    } else {
//       res.send(`Incorrect password!`)
     
//     }
//   } else {
//     res.send(`Unable to find the username ${req.body.username}. Please register for new users.`)
//   }

// })

// app.get('/', (req, res) => {
//    res.send('Plastik HItam Jom!')
// })

// app.listen(port, () => {
//    console.log(`Example app listening on port ${port}`)
// })

// const { MongoClient, ServerApiVersion } = require('mongodb');
// const uri = "mongodb+srv://b022210198:1234556@clusterberr2423.5imns99.mongodb.net/?retryWrites=true&w=majority&appName=ClusterBERR2423";

// // Create a MongoClient with a MongoClientOptions object to set the Stable API version
// const client = new MongoClient(uri, {
//   serverApi: {
//     version: ServerApiVersion.v1,
//     strict: true,
//     deprecationErrors: true,
//   }
// });

// async function run() {
//   try {
//     // Connect the client to the server	(optional starting in v4.7)
//     await client.connect();
//     // Send a ping to confirm a successful connection
//     await client.db("admin").command({ ping: 1 });
//     console.log("Pinged your deployment. You successfully connected to MongoDB!");
//   } finally {
//     // Ensures that the client will close when you finish/error
//     // await client.close();
//   }
// }
// run().catch(console.dir);

