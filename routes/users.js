var express = require('express');
var router = express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;

var User = require('../models/user');

// Register
router.get('/register', function (req, res) {
	res.render('register');
});

// Login
router.get('/login', function (req, res) {
	res.render('login');
});

// Register User
router.post('/register', function (req, res) {
	var name = req.body.name;
	var email = req.body.email;
	var lname = req.body.lname;
	var password = req.body.password;
	var password2 = req.body.password2;


	// Validation
	req.checkBody('name', 'Name is required').notEmpty();
	req.checkBody('lname', 'Last name is required').notEmpty();
	req.checkBody('email', 'Email is required').notEmpty();
	req.checkBody('email', 'Email is not valid').isEmail();
	req.checkBody('password', 'Password is required').notEmpty();
	req.checkBody('password2', 'Passwords do not match').equals(req.body.password);

	var errors = req.validationErrors();

	if (errors) {
		res.render('register', {
			errors: errors
		});
	} else {
		//checking for email is already taken
		User.findOne({
			email: {
				"$regex": "^" + email + "\\b",
				"$options": "i"
			}
		}, function (err, mail) {
			if (mail) {
				res.render('register', {
					mail: mail
				});
			} else {
				var newUser = new User({
					name: name,
					email: email,
					lname: lname,
					password: password
				});
				User.createUser(newUser, function (err, user) {
					if (err) throw err;
					console.log(user);
				});
				req.flash('success_msg', 'You are registered and can now login');
				res.redirect('/users/login');
			}
		});
	}
});

passport.use(new LocalStrategy(
	function (email, password, done) {
		User.getUserByEmail(email, function (err, user) {
			if (err) throw err;
			if (!user) {
				return done(null, false, {
					message: 'Unknown User'
				});
			}

			User.comparePassword(password, user.password, function (err, isMatch) {
				if (err) throw err;
				if (isMatch) {
					return done(null, user);
				} else {
					return done(null, false, {
						message: 'Invalid password'
					});
				}
			});
		});
	}));

passport.serializeUser(function (user, done) {
	done(null, user.id);
});

passport.deserializeUser(function (id, done) {
	User.getUserById(id, function (err, user) {
		done(err, user);
	});
});

router.post('/login', 
// function (req, res) {
// 	var users = req.app;
// 	var email = req.body.email;
// 	var password = req.body.password;
// 	var data;
// 	if (email.length > 0 && password.length > 0) {
// 		data = {
// 			email: email,
// 			password: password
// 		};
// 	} else {
// 		res.json({
// 			status: 0,
// 			message: err
// 		});
// 	}
// 	users.findOne(data, function (err, user) {
// 		if (err) {
// 			res.json({
// 				status: 0,
// 				message: err
// 			});
// 		}
// 		if (!user) {
// 			res.json({
// 				status: 0,
// 				message: "not found"
// 			});
// 		}
// 		res.json({
// 			status: 1,
// 			id: user._id,
// 			message: "success"
// 		});
// 	}) 
// });
passport.authenticate('local', {
	successRedirect: '/',
	failureRedirect: '/users/login',
	failureFlash: true
}),
function (req, res) {
	res.redirect('/');
});

router.get('/logout', function (req, res) {
	req.logout();

	req.flash('success_msg', 'You are logged out');

	res.redirect('/users/login');
});

module.exports = router;