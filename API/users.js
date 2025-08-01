const express = require('express');
const { check, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sql = require('../config/db');
const dotenv = require('dotenv');

dotenv.config();
const router = express.Router();

// @route   POST /api/users
// @desc    Register new user
// @access  Public
router.post(
  '/',
  [
    check('first_name').notEmpty().withMessage('First name is required'),
    check('last_name').notEmpty().withMessage('Last name is required'),
    check('birthday').isISO8601().toDate().withMessage('Valid birthday is required'),
    check('gender').isIn(['Male', 'Female', 'Other']).withMessage('Invalid gender'),
    check('username').matches(/^[a-zA-Z0-9]{4,20}$/).withMessage('Username must be 4-20 alphanumeric characters'),
    check('email_address').isEmail().withMessage('Valid email is required'),
    check('phone_number').matches(/^\+63[0-9]{10}$/).withMessage('Phone number must be in +63 format'),
    check('location_address').notEmpty().withMessage('Location address is required'),
    check('location_lat').isFloat({ min: -90, max: 90 }).withMessage('Invalid latitude'),
    check('location_lng').isFloat({ min: -180, max: 180 }).withMessage('Invalid longitude'),
    check('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
    check('profile_picture_url').optional().isURL().withMessage('Profile picture must be a valid URL'),
    check('has_accepted_terms').isBoolean().custom(val => val === true).withMessage('Terms must be accepted'),
    check('is_email_verified').isBoolean().custom(val => val === true).withMessage('Email must be verified'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const {
      first_name,
      last_name,
      birthday,
      gender,
      username,
      email_address,
      phone_number,
      location_address,
      location_lat,
      location_lng,
      password,
      profile_picture_url,
      has_accepted_terms,
      is_email_verified,
    } = req.body;

    try {
      // Check if email or username already exists
      const existingUser = await sql`
        SELECT * FROM teleo_users WHERE email_address = ${email_address} OR username = ${username}
      `;
      if (existingUser.length > 0) {
        return res.status(400).json({ errors: [{ msg: 'User already exists' }] });
      }

      // ✅ Hash the password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      // ✅ Insert user with hashed password
      const [user] = await sql`
        INSERT INTO teleo_users (
          first_name, last_name, birthday, gender, username,
          email_address, phone_number, location_address,
          location_lat, location_lng, password, profile_picture_url,
          has_accepted_terms, is_email_verified
        ) VALUES (
          ${first_name}, ${last_name}, ${birthday}, ${gender}, ${username},
          ${email_address}, ${phone_number}, ${location_address},
          ${location_lat}, ${location_lng}, ${hashedPassword}, ${profile_picture_url},
          ${has_accepted_terms}, ${is_email_verified}
        )
        RETURNING id, first_name, last_name, email_address, username
      `;

      const payload = {
        user: { id: user.id },
      };

      jwt.sign(
        payload,
        process.env.JWT_SECRET,
        { expiresIn: '1h' },
        (err, token) => {
          if (err) throw err;
          res.status(201).json({
            message: 'User registered successfully',
            token,
            user,
          });
        }
      );
    } catch (err) {
      console.error('Register error:', err);
      res.status(500).json({ error: 'Server error' });
    }
  }
);git remote add origin https://github.com/Johnphilippar/Registration-Login.git

module.exports = router;
