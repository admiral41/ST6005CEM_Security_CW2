const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');

const sendEmail = async (receiverEmail, subject, replacements, emailType = 'upload') => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.GMAIL_USER,  
            pass: process.env.GMAIL_PASS  
        }
    });

    let templatePath = '';

    if (emailType === 'upload') {
        templatePath = path.join(__dirname, '../templates/uploadFileTemplate.html');
    } else if (emailType === 'accountLock') {
        templatePath = path.join(__dirname, '../templates/accountLockTemplate.html');
    } else if (emailType === 'verifyEmail') {  // For email verification
        templatePath = path.join(__dirname, '../templates/verifyEmailTemplate.html');
    }

    try {
        // Check if the template file exists before reading
        if (!fs.existsSync(templatePath)) {
            throw new Error(`Template file not found: ${templatePath}`);
        }

        let htmlContent = fs.readFileSync(templatePath, 'utf8');

        // Replace placeholders with actual values
        Object.keys(replacements).forEach(key => {
            const regex = new RegExp(`{{${key}}}`, 'g');
            htmlContent = htmlContent.replace(regex, replacements[key] || '');
        });

        const mailOptions = {
            from: `MyEncrypt <${process.env.GMAIL_USER}>`,
            to: receiverEmail,
            subject: subject,
            html: htmlContent,
            attachments: [
                {
                    filename: 'logo.png',
                    path: path.join(__dirname, '../templates/logo.png'),
                    cid: 'logo' // Use this CID in the img src
                },
                {
                    filename: 'footerLogo.png',
                    path: path.join(__dirname, '../templates/logo.png'),
                    cid: 'footerLogo' // Use this CID in the img src
                }
            ]
        };

        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent: ' + info.response);
        return { success: true, data: info.response };
    } catch (error) {
        console.error('Error sending email:', error.message);
        return { success: false, error: error.message };
    }
};

module.exports = sendEmail;
