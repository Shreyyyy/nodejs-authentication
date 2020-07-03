const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
const session = require('express-session');
const ObjectID = require('mongodb').ObjectID;
// Load User model
const User = require('../models/User');
const { ensureAuthenticated, forwardAuthenticated } = require('../config/auth');

// Login Page
router.get('/login', forwardAuthenticated, (req, res) => res.render('login'));

// Register Page
router.get('/register', forwardAuthenticated, (req, res) => res.render('register'));
router.get('/update-profile', ensureAuthenticated, (req, res) => res.render('update-profile'));
// Register
router.post('/register', (req, res) => {
  const { name, email, password, password2,admincode} = req.body;
  let errors = [];
  
  if (!name || !email || !password || !password2) {
    errors.push({ msg: 'Please enter all fields' });
  }

  if (password != password2) {
    errors.push({ msg: 'Passwords do not match' });
  }


  if (errors.length > 0) {
    res.render('register', {
      errors,
      name,
      email,
      password,
      password2
    });
  } else {
    User.findOne({ email: email }).then(user => {
      if (user) {
        errors.push({ msg: 'Email already exists' });
        res.render('register', {
          errors,
          name,
          email,
          password,
          password2
        });
      } else {
        const newUser = new User({
          name,
          email,
          password,
        });
        if(admincode == 'secretcode123'){
          newUser.role = "admin";
        }
        bcrypt.genSalt(10, (err, salt) => {
          bcrypt.hash(newUser.password, salt, (err, hash) => {
            if (err) throw err;
            newUser.password = hash;
            newUser
              .save()
              .then(user => {
                req.flash(
                  'success_msg',
                  'You are now registered and can log in'
                );
                res.redirect('/user/login');
              })
              .catch(err => console.log(err));
          });
        });
      }
    });
  }
});

// Login
router.post('/login', (req, res, next) => {
  res.set('Cache-Control', 'no-cache, private, no-store, must-revalidate, max-stale=0, post-check=0, pre-check=0');
  passport.authenticate('local', {
    successRedirect: '/user/dashboard',
    failureRedirect: '/user/login',
    failureFlash: true
  })(req, res, next);
});


//Profile
router.get('/dashboard', ensureAuthenticated, (req, res) =>
  res.render('dashboard', {
    user: req.user
  })
);

//  profile edit
// --------------------------------------------------
router.post('/update-profile', (req, res) => {
  const { name, address, linkedin, phonenum} = req.body;
  const _id = ObjectID(req.session.passport.user);

  User.updateOne({ _id }, { $set: { name, address, linkedin, phonenum } }, (err) => {
    if (err) {
      throw err;
    }
    res.redirect('/user/dashboard');
  });    
});

// --------------------------------------------------




// Logout
router.get('/logout', (req, res) => {
  req.logout();
  
  req.flash('success_msg', 'You are logged out');
  req.session.destroy();
  res.set('Cache-Control', 'no-cache, private, no-store, must-revalidate, max-stale=0, post-check=0, pre-check=0');
  
  res.redirect('/user/login');
});

module.exports = router;
