const mongoose = require("mongoose");

const fileSchema = new mongoose.Schema({
    fileName: {
        type: String,
        required: [true, "Please provide file name"]
    },
    password: {
        type: String,
        required: true
    },
    originalName: {
        type: String,
        required: [true, "Please add original file name"]
    },
    path: {
        type: String,
        required: [true, "Please provide path name"]
    },
    downloadLink: {
        type: String,
        required: [true, "Please provide download link"]
    },
    extension: {
        type: String,
        required: [true, "Please provide file extension"]
    },
    uploadedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    uploadDate: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model("File", fileSchema);
