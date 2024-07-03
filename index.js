const express = require("express");
const dotenv = require("dotenv");
const connectToDB = require('./database/db');
const path = require("path");
const fileRoutes = require('./routes/fileRoutes');
const userRoutes = require('./routes/userRoutes');
const helmet = require('helmet');
const xssClean = require('xss-clean');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const requestIp = require('request-ip');
const cors = require('cors');
const fs = require('fs');
const https = require('https');
const auditLogMiddleware = require('./middleware/auditLog'); // Importing the audit log middleware

// Creating an Express app
const app = express();

// Configure dotenv to use .env
dotenv.config();

// Middleware to allow requests from the frontend
const corsOptions = {
    origin: 'https://localhost:3000',
    methods: ["GET, POST, PUT, DELETE"],
    credentials: true,
    optionsSuccessStatus: 200 
};
app.use(cors(corsOptions));

// Connecting to DB
connectToDB();

// Middleware to secure HTTP headers
app.use(helmet());

// Middleware to sanitize user input against XSS attacks
app.use(xssClean());

// Middleware to limit repeated requests to public APIs
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later'
});
app.use(limiter);

// Middleware to sanitize data against NoSQL injection
app.use(mongoSanitize());

// Middleware to get client IP
app.use(requestIp.mw());

// Middleware to log specific actions
app.use(auditLogMiddleware); // Using the audit log middleware

// Accept JSON data
app.use(express.json());

// Accept form data
app.use(express.urlencoded({ extended: true }));

// Upload file routes
app.use(
    "/uploads",
    express.static(path.join(__dirname, "/uploads"))
);

const options = {
    key: fs.readFileSync("key.pem"),
    cert: fs.readFileSync("cert.pem"),
};

// Define routes
app.use('/api/files', fileRoutes); // Use file routes
app.use('/api/users', userRoutes); // Use user routes

// Defining port
const PORT = process.env.PORT || 5000;
https.createServer(options, app).listen(PORT, () => {
  console.log(`HTTPS Server is running on port ${PORT}`);
});
