const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const config = require('config');
const jwt = require('jsonwebtoken');
const auth = require('../../middleware/auth');

const User = require('../../models/User');

// @route POST api/auth
// @desc Authenticate user
// @access public

router.post('/', (req, res) => {
  const { email, password } = req.body;

  // Simple validation
  if ( !email || !password) {
    return res.status(400).json({ msg: 'please enter all fields ' });
  }

  // Check if user already exists
  User.findOne({ email })
    .then(user => {
      if (!user) return res.status(400).json({ msg: 'user does not exists ' });
      
      // Validate password
      bcrypt.compare(password, user.password)
        .then(isMatch => {
          if(!isMatch) return res.status(400).json({ msg: 'invalid credentials '});

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

// get the current user's data by using the token,
// this is how we constantly validate the user that's 
// logged in on the front end.
// this route will take the token and return the data.

// @route GET api/auth/user
// @desc Get user data
// @access private
router.get('/user', auth, (req, res) => {
  User.findById(req.user.id)
    .select('-password')
    .then(user => res.json(user));
});



module.exports = router;

