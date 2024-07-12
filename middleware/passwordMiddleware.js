const User = require('../models/userModel');
const bcrypt = require('bcryptjs');

exports.checkPasswordHistory = async (req, res, next) => {
    try {
        const { newPassword } = req.body;
        const user = await User.findById(req.user._id);

        const isPasswordUsedBefore = await Promise.all(user.passwordHistory.map(async (oldPassword) => {
            return await bcrypt.compare(newPassword, oldPassword);
        }));

        if (isPasswordUsedBefore.includes(true)) {
            return res.status(400).json({ msg: 'You cannot reuse your previous passwords' });
        }

        next();
    } catch (error) {
        console.error('Error checking password history:', error);
        res.status(500).json({ msg: 'Server error' });
    }
};

exports.checkPasswordExpiry = async (req, res, next) => {
    try {
        const user = await User.findOne({ email: req.body.email });

        if (user) {
            const currentDate = new Date();
            const expiryDate = new Date(user.passwordUpdatedAt);
            expiryDate.setDate(expiryDate.getDate() + 90);

            if (currentDate > expiryDate) {
                return res.status(403).json({ msg: 'Your password has expired, please update it.' });
            }
        }

        next();
    } catch (error) {
        console.error('Error checking password expiry:', error);
        res.status(500).json({ msg: 'Server error' });
    }
};
