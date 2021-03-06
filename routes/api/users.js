const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const config = require('config');
const jwt = require('jsonwebtoken');

const User = require('../../models/User');

// @route POST api/users
// @desc register new user
// @access public

router.post('/', (req, res) => {
  const { name, email, password } = req.body;

  // Simple validation
  if (!name || !email || !password) {
    return res.status(400).json({ msg: 'please enter all fields '});
  }

  // Check if user already exists
  User.findOne({ email })
    .then(user => {
      if (user) return res.status(400).json({ msg: 'user already exists '});

      const newUser = new User({ 
        name,
        email, 
        password
      });

      bcrypt.genSalt(10, (err, salt) => {
        // eslint-disable-next-line no-shadow
        bcrypt.hash(newUser.password, salt, (err, hash) => {
          if (err) throw err;
            newUser.password = hash;
            newUser.save()
              // eslint-disable-next-line no-shadow
              .then(user => {

                jwt.sign(
                  { id: user.id },
                  config.get('jwtSecret'),
                  { expiresIn: 3600 },
                  // eslint-disable-next-line no-shadow
                  (err, token) => {
                    if (err) throw err;
                    res.json({
                      token,
                      user: {
                        id: user.id,
                        name: user.name,
                        email: user.email
                      }
                    });
                  }
                );

                
              });
        });
      });
    });
});



module.exports = router;

