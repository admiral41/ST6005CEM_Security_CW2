const express = require("express");
const dotenv = require("dotenv");
const connectToDB = require('./database/db');

// creating an express app
const app = express();
// configure dotenv to use .env
dotenv.config();
// Defining port
const PORT = process.env.PORT || 5000;
// running the server on port 5000
app.listen(PORT, () => {
    console.log(`Listening on port: ${PORT}`);
});