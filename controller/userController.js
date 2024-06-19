const bcrypt = require('bcryptjs'); 
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const User = require('../models/userModel');
const xss = require('xss');
const axios = require('axios');
const requestIp = require('request-ip');
const sendEmail = require('../middleware/sendEmail');
const crypto = require('crypto');

// Register user
exports.registerUser = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;

    try {
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ msg: 'User already exists' });
        }

        const salt = await bcrypt.genSalt(12);
        const hashedPassword = await bcrypt.hash(password, salt);

        const verificationToken = crypto.randomBytes(32).toString('hex');
        const verificationLink = `https://localhost:3000/verify/${verificationToken}`;

        user = new User({
            name: xss(name),
            email: xss(email),
            password: hashedPassword,
            passwordHistory: [hashedPassword],
            verificationToken,
            isVerified: false
        });

        await user.save();

        await sendEmail(
            user.email,
            'Verify Your Email Address',
            { verificationLink: verificationLink },
            'verifyEmail'
        );

        res.status(201).json({
            status: "Registered",
            msg: "Registration successful. Please check your email to verify your account.",
            user: { id: user.id, name: user.name, email: user.email }
        });

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
};