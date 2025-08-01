const express = require('express');
const { check, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sql = require('../config/db');
const dotenv = require('dotenv');
const auth = require('../middleware/auth');

dotenv.config();

const router = express.Router();

// @route    GET /api/auth
// @desc     Protected route to get current user info
// @access   Private
router.get('/', auth, async (req, res) => {
  try {
    const [user] = await sql`
      SELECT id, first_name, last_name, email_address 
      FROM teleo_users 
      WHERE id = ${req.user.id}
    `;

    if (!user) {
      return res.status(404).json({ msg: 'User not found' });
    }

    res.json({ msg: 'Protected data access granted', user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server Error' });
  }
});

// @route   POST /api/auth
// @desc    Login user & return JWT token
// @access  Public
router.post(
  '/',
  [
    check('email_address', 'Please include a valid email').isEmail(),
    check('password', 'Password is required').exists(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email_address, password } = req.body;

    try {
      const result = await sql`
        SELECT * FROM teleo_users 
        WHERE email_address = ${email_address}
      `;
      const user = result[0];

      if (!user) {
        return res
          .status(400)
          .json({ errors: [{ msg: 'Invalid Credentials (email not found)' }] });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res
          .status(400)
          .json({ errors: [{ msg: 'Invalid Credentials (wrong password)' }] });
      }

      // Optional: Check if email is verified
      if (!user.is_email_verified) {
        return res.status(403).json({
          errors: [{ msg: 'Please verify your email before logging in' }],
        });
      }

      const payload = {
        user: {
          id: user.id,
        },
      };

      jwt.sign(
        payload,
        process.env.JWT_SECRET,
        { expiresIn: '1h' },
        (err, token) => {
          if (err) throw err;

          res.json({
            message: 'Login successful',
            token,
            user: {
              id: user.id,
              first_name: user.first_name,
              last_name: user.last_name,
              email_address: user.email_address,
              username: user.username,
            },
          });
        }
      );
    } catch (err) {
      console.error('Login error:', err.message);
      res.status(500).send('Server error');
    }
  }
);

module.exports = router;
