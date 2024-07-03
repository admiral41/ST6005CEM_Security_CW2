const fs = require('fs');
const moment = require('moment'); 
const auditLogStream = fs.createWriteStream('./logs/audit.log', { flags: 'a' });
function auditLogMiddleware(req, res, next) {
    const timestamp = moment().format('YYYY-MM-DD HH:mm:ss');
    const logEntry = `[${timestamp}] ${req.method} ${req.url}`;
        if (req.url === '/api/users/register' && req.method === 'POST') {
        const customLogEntry = `${logEntry} - User registration attempt`;
        auditLogStream.write(customLogEntry + '\n');
    }
    if (req.url === '/api/users/login' && req.method === 'POST') {
        const customLogEntry = `${logEntry} - User login attempt`;
        auditLogStream.write(customLogEntry + '\n');
    }
    if (req.url === '/api/files/upload' && req.method === 'POST') {
        const customLogEntry = `${logEntry} - File upload attempt by user: ${req.user ? req.user._id : 'Unknown'}`;
        auditLogStream.write(customLogEntry + '\n');
    }
    if (req.url.includes('/api/files/download') && req.method === 'GET') {
        const customLogEntry = `${logEntry} - File download attempt by user: ${req.user ? req.user._id : 'Unknown'}`;
        auditLogStream.write(customLogEntry + '\n');
    }
    if (req.url.includes('/api/files/delete') && req.method === 'DELETE') {
        const customLogEntry = `${logEntry} - File deletion attempt by user: ${req.user ? req.user._id : 'Unknown'}`;
        auditLogStream.write(customLogEntry + '\n');
    }
    next();
}
module.exports = auditLogMiddleware;
