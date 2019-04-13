const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const KnexSessionStore = require('connect-session-knex')(session);

const db = require('./data/dbConfig.js');
const Users = require('./users/users-model.js');

const server = express();

const sessionConfig = {
  name: 'cookieMonster',
  secret: 'idkwtfthisdoes',
  cookie: {
    maxAge: 1000 * 60 * 21, 
    secure: false, 
    httpOnly: true, 
  },
  resave: false, 
  saveUninitialized: false, 
  store: new KnexSessionStore({
    knex: db,
    tablename: 'sessions',
    sidfieldname: 'sid',
    createtable: true,
    clearInterval: 1000 * 60 * 30,
  })
};

server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session(sessionConfig));

server.get('/', (req, res) => {
  res.send('Welcome to the Jungle');
});

server.post('/api/register', (req, res) => {
  let user = req.body;
  user.password = bcrypt.hashSync(user.password, 4);

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        req.session.user = user;
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.get('/api/logout', (req, res) => {
  if (req.session) {
    req.session.destroy(err => {
      if (err) {
        res.status(500).json({ message: 'Failed Log Out'})
      } else {
        res.status(200).json({ message: 'Successfully Logged Out'})
      }
    })
  } else {
    res.status(200).json({ message: 'Successfully Logged Out'})
  }
})

// server.get('/api/users', restricted, only('joshk'), (req, res) => {
server.get('/api/users', restricted, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

function only(username) {
  return function (req, res, next) {
    if (req.headers.username === username) {
      next();
  } else {
    res.status(403).json({ message: `You are not ${username}` })
  }
 }
}

function restricted(req, res, next) {
  if (req.session && req.session.user) {
    next();
  } else {
    res.status(401).json({ message: 'Invalid Credentials'});
  }
}


//   const { username, password } = req.headers;
//   if (username && password) {
//     Users.findBy({ username })
//       .first()
//       .then(user => {
//         if (user && bcrypt.compareSync(password, user.password)) {
//           next();
//         } else {
//           res.status(401).json({ message: 'Invalid Credentials' });
//         }
//       })
//       .catch(error => {
//         res.status(500).json(error);
//       });
//   } else {
//     res.status(401).json({ message: 'please provide credentials'})
//   }
// }

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
