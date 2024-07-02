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

// creating an express app
const app = express();
// configure dotenv to use .env
dotenv.config();
// middleware to allow requests from the frontend
const corsOptions = {
    origin: true,
    methods: ["GET, POST, PUT, DELETE"],
    credentials: true,
    optionsSuccessStatus: 200 
};
app.use(cors(corsOptions));


// connecting to db
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

// accept json data
app.use(express.json());
// accept form data
app.use(express.urlencoded({ extended: true }));

// Upload file routes
app.use(
    "/uploads",
    express.static(path.join(__dirname, "/uploads"))
);

app.use('/api/users', userRoutes); // Use user routes

// Defining port
const PORT = process.env.PORT || 5000;
// running the server on port 5000
app.listen(PORT, () => {
    console.log(`Listening on port: ${PORT}`);
});