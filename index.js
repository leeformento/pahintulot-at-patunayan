const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const KnexSessionStore = require('connect-session-knex')(session); // constructor = uppercase


const db = require('./database/dbConfig.js');

const server = express();

// cookies are not hashed. they are encrypted.
const sessionConfig = {
  secret: 'nobody.tosses.a.dwarf.!', // periods for security
  name: 'monkey', // generate cookie, default name: connect:sid. but we dont want people to know we use session]
  httpOnly: true, // JS can't access this
  resave: false,
  saveUninitialized: false, // laws!
  cookie: {
    secure: false,// restrict so a cookie is only saved when it is secured - https : put true. but we use false to test
    maxAge: 1000 * 60 * 10 // 1 minute, when it expires. hey, your session expired! -- this is it
  },
  store: new KnexSessionStore ({
    tablename: 'session',
    sidfield: 'sid', //sessionid
    knex: db,
    createtable: true,
    clearInterval: 1000 * 60 * 60, // how long to wait before pkg check db and delete, every hour clean up

  })
}


server.use(session(sessionConfig))

server.use(express.json());
server.use(cors());

server.get('/', (req, res) => {
  res.send('Its Alive!');
});

server.post('/register', (req, res) => {
  const credentials = req.body; // store body of post req un credentials var
  // hash the password
  const hash = bcrypt.hashSync(credentials.password, 14) // 2^14 times, hash the pw
  credentials.password= hash; // store hashed pw on credentials
  // save user
  db('users')
  .insert(credentials)
  .then(ids => {
    const id = ids[0];
    req.session.username = credentials.username // save that session, i want to put a username in that session
    res.status(201).json({ newUserId: id})
  })
  .catch(err => {
    res.status(500).json(err)
  })

})

server.post('/login', (req, res) => {
  const creds = req.body;
  db('users')
  .where({ username: creds.username})
  .first()
  .then(user => {
    // found user - right password or not (compare sync) -- compare to user password (hash same, found)
    if (user && bcrypt.compareSync(creds.password, user.password)) {
      req.session.username = user.username // save that session, i want to put a username in that session
      res.status(200).json({ welcome: user.username})

    } else {
      res.status(404).json({ message: 'You shall not pass!'})
    }
  })
  .catch(err => res.status(500).json(err))
})
// protect this route, only authenticated users should see it
server.get('/api/users', protected, (req, res) => {
  // only if the device is logged in
    db('users')
    .select('id', 'username', 'password')
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

// LOGOUT 
server.get('/logout', (req,res) => {
  if(req.session) {
    req.session.destroy(err => {
      if (err) {
        res.send('you cant leave!')
      } else {
        res.send('good bye!')
      }
    })
  }

})

function protected(req, res, next) {
  if (req.session && req.session.username) {

    next();
  } else {
    res.status(401).send('Not authorized!')
  }
} 

// Unhandled rejection Error: Can't set headers after they are sent
// NOT ENDING RESPONSE AT LINE 76
server.listen(3300, () => console.log('\nrunning on port 3300\n'));
