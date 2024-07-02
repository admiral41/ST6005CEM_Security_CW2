const express = require('express');
const { body } = require('express-validator');
const { registerUser, loginUser, unlockAccount,changePassword,verifyEmail } = require('../controller/userController');
const router = express.Router();
const authMiddleware = require('../middleware/authMiddleware');
const passwordMiddleware = require('../middleware/passwordMiddleware');
const User = require('../models/userModel');

router.post(
    '/register',
    [
        body('name', 'Name is required').not().isEmpty(),
        body('email', 'Please include a valid email').isEmail(),
        body('password')
            .isLength({ min: 8, max: 12 }).withMessage('Password must be between 8 and 12 characters')
            .matches(/[A-Z]/).withMessage('Password must contain an uppercase letter')
            .matches(/\d/).withMessage('Password must contain a number')
            .matches(/[!@#$%^&*]/).withMessage('Password must contain a special character')
    ],
    registerUser
);

router.post(
    '/login',
    [
        body('email', 'Please include a valid email').isEmail(),
        body('password', 'Password is required').exists()
    ],
    passwordMiddleware.checkPasswordExpiry, // Middleware to check if password is expired
    loginUser
);
module.exports = router;
