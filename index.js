const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./database/dbConfig.js');

const server = express();

server.use(express.json());
server.use(cors());

server.get('/', (req, res) => {
  res.send('Its Alive!');
});

server.post('/register', (req, res) => {
  const credentials = req.body;
  // hash the password
  const hash = bcrypt.hashSync(credentials.password, 14) // 2^14 times
  credentials.password= hash;
  // save user
  db('users')
  .insert(credentials)
  .then(ids => {
    const id = ids[0];
    res.status(201).json({ newUserId: id})
  })
  .catch(err => {
    res.status(500).json(err)
  })

})

const jwtSecret = 'nobody tosses a dwarf!';

function generateToken(user) {
  const jwtPayload = {
    ...user,
    hello: 'Lee',
    role: 'admin'
  }
  const jwtOptions = {
    expiresIn: '3m'
  }
  return jwt.sign(jwtPayload, jwtSecret, jwtOptions)
}

server.post('/login', (req, res) => {
  const creds = req.body;
  db('users')
    .where({ username: creds.username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(creds.password, user.password)) {
        const token = generateToken(user)
        res.status(200).json({ welcome: user.username, token });
      } else {
        res.status(401).json({ message: 'you shall not pass!' });
      }
    })
    .catch(err => {
      res.status(500).json({ err });
    });
});

// protect this route, only authenticated users should see it
server.get('/users', protected, (req, res) => {
  console.log('\n*** decoded token info **\n', req.decodedToken);
  db('users')
    .select('id', 'username', 'password')
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

function protected(req, res, next) {
  // authentication tokens are normally sent as header instead of body
  const token = req.headers.authorization;
  if (token) {
    jwt.verify(token, jwtSecret, (err, decodedToken) => {
      if (err) {
        // token verification failed
        res.status(401).json({ message: 'Invalid token'});
      } else {
        // token is valid
        next(); 
        req.decodedToken = decodedToken; // any subsequent middleware of route handler have access to this
        next();
      }
    })
  } else {
    res.status(401).json({ message: 'No token provided' });
  }
}

server.listen(3300, () => console.log('\nrunning on port 3300\n'));