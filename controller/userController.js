const bcrypt = require('bcryptjs'); 
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const User = require('../models/userModel');
const xss = require('xss');
const axios = require('axios');
const requestIp = require('request-ip');
const sendEmail = require('../middleware/sendEmail');
const crypto = require('crypto');

// Function to get geolocation from IP
const getGeolocation = async (ip) => {
    try {
        const response = await axios.get(`https://api.ipgeolocation.io/ipgeo?apiKey=${process.env.ABSTRACT_API_KEY}&ip=${ip}`);
        return {
            city: response.data.city,
            country: response.data.country_name,
            latitude: response.data.latitude,
            longitude: response.data.longitude
        };
    } catch (error) {
        console.error("Error fetching geolocation:", error);
        return { city: "unknown", country: "unknown", latitude: null, longitude: null };
    }
};

// Function to get the real IP address
const getRealIp = (req) => {
    let ip = requestIp.getClientIp(req);
    if (req.headers['x-forwarded-for']) {
        ip = req.headers['x-forwarded-for'].split(',')[0];
    }
    if (ip === '::1' || ip === '127.0.0.1') {
        ip = '27.34.90.106'; // Replace with your actual IP for testing purposes
    }
    return ip;
};

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
exports.verifyEmail = async (req, res) => {
    try {
        const { verificationToken } = req.params;
        const user = await User.findOne({ verificationToken });

        if (!user) {
            return res.status(400).json({ msg: 'Invalid or expired verification link.' });
        }

        // Update the user's verification status
        user.isVerified = true;
        user.verificationToken = undefined;

        await user.save();

        res.status(200).json({ msg: 'Email verified successfully. You can now log in.' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
};


// Login user
exports.loginUser = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
        let user = await User.findOne({ email });
        const ip = getRealIp(req);
        const location = await getGeolocation(ip);

        if (!user) {
            return res.status(400).json({ msg: 'Email does not exist' });
        }

        // Check if the user's email has been verified
        if (!user.isVerified) {
            return res.status(403).json({ msg: 'Please verify your email before logging in.' });
        }

        if (user.accountLocked) {
            if (user.resetToken) {
                return res.status(403).json({ msg: 'Your account is locked. Please check your email to unlock your account.' });
            } else {
                const resetToken = crypto.randomBytes(32).toString('hex');
                user.resetToken = resetToken;
                const unlockLink = `https://localhost:3000/unlock/${resetToken}`;
                
                await sendEmail(
                    user.email, 
                    'Account Locked: Unlock Your Account', 
                    { unlockLink }, 
                    'accountLock'
                );
                
                await user.save();

                return res.status(403).json({ msg: 'Your account has been locked due to multiple failed login attempts. Please check your email to unlock your account.' });
            }
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            user.failedLoginAttempts += 1;
            user.logs.push({
                action: 'Failed login attempt',
                ip,
                location: `${location.city}, ${location.country}`,
                latitude: location.latitude,
                longitude: location.longitude
            });

            if (user.failedLoginAttempts >= 3) {
                user.accountLocked = true;
                if (!user.resetToken) {
                    const resetToken = crypto.randomBytes(32).toString('hex');
                    user.resetToken = resetToken;
                    const unlockLink = `https://localhost:3000/unlock/${resetToken}`;
                    
                    await sendEmail(
                        user.email, 
                        'Account Locked: Unlock Your Account', 
                        { unlockLink }, 
                        'accountLock'
                    );
                }

                await user.save();
                return res.status(403).json({ msg: 'Your account has been locked due to multiple failed login attempts. Please check your email to unlock your account.' });
            }

            await user.save();
            return res.status(400).json({ msg: 'Invalid password' });
        }

        // Check if password has expired
        const currentDate = new Date();
        const expiryDate = new Date(user.passwordUpdatedAt);
        expiryDate.setDate(expiryDate.getDate() + 90);

        if (currentDate > expiryDate) {
            return res.status(403).json({ msg: 'Your password has expired, please update it.' });
        }

        user.failedLoginAttempts = 0; // Reset failed login attempts on successful login
        user.resetToken = undefined; // Clear reset token after successful login
        const payload = {
            _id: user.id
        };

        jwt.sign(
            payload,
            process.env.JWT_SECRET, // Use the secret key from environment variables
            { expiresIn: '30d' }, // Set the token to expire in 30 days
            async (err, token) => {
                if (err) return res.status(400).json({ error: "Error with payload!" });

                user.logs.push({
                    action: 'User logged in',
                    ip,
                    location: `${location.city}, ${location.country}`,
                    latitude: location.latitude,
                    longitude: location.longitude
                });
                await user.save();

                res.json({
                    status: "Logged In",
                    token,
                    user: {
                        id: user.id,
                        name: user.name,
                        email: user.email,
                        logs: user.logs
                    }
                });
            }
        );

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
};
