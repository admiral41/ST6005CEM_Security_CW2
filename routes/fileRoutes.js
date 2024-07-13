const express = require("express");
const router = express.Router();
const multer = require("multer");
const bcrypt = require('bcryptjs'); // Use bcryptjs only
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const File = require("../models/fileModel");
const User = require("../models/userModel");
const authMiddleware = require('../middleware/authMiddleware');
const sendEmail = require('../middleware/sendEmail');
const { v4: uuidv4 } = require('uuid');
const allowedExtensions = [
    "pdf", "docx", "doc", "xls", "xlsx", "csv", "txt", "rtf", "html", "zip",
    "mp3", "m4a", "wma", "mpg", "flv", "avi", "jpg", "jpeg", "png", "gif",
    "ppt", "pptx", "wav", "mp4", "m4v", "wmv", "avi", "epub"
];
const upload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => {
            cb(null, "uploads/");
        },
        filename: (req, file, cb) => {
            cb(null, Date.now() + "-" + file.originalname);
        }
    }),
    fileFilter: (req, file, cb) => {
        const fileExtension = file.originalname.split('.').pop().toLowerCase();
        if (!allowedExtensions.includes(fileExtension)) {
            return cb(new Error("Invalid file type"));
        }
        cb(null, true);
    },
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB file size limit
});


router.post("/upload", authMiddleware, upload.single("encryptedFile"), async (req, res) => {
    try {
        const { originalName, password, receiverEmail } = req.body;

        if (!req.file) {
            return res.status(400).json({ message: "No file uploaded" });
        }

        const hashedPassword = bcrypt.hashSync(password, 10);
        const fileId = uuidv4();
        const downloadLink = `https://localhost:3000/download`; // Correct frontend download link

        // Encrypt the file
        const fileBuffer = fs.readFileSync(req.file.path);
        const cipher = crypto.createCipher('aes-256-cbc', password);
        let encrypted = cipher.update(fileBuffer);
        encrypted = Buffer.concat([encrypted, cipher.final()]);

        fs.writeFileSync(req.file.path, encrypted);

        const newFile = new File({
            fileName: req.file.filename,
            password: hashedPassword,
            originalName,
            path: req.file.path,
            downloadLink: `https://localhost:5000/api/files/download/${fileId}`, // Backend download link for internal use
            extension: req.file.mimetype,
            uploadedBy: req.user._id
        });

        await newFile.save();

        const user = await User.findById(req.user._id);
        user.files.push(newFile._id);
        await user.save();

        if (receiverEmail) {
            const emailResult = await sendEmail(
                receiverEmail,
                'Here is your File ID!',
                { senderName: 'Your App', fileID: fileId, downloadLink: downloadLink },
                'upload'
            );

            if (!emailResult.success) {
                return res.status(500).json({ message: "File uploaded, but error sending email", error: emailResult.error });
            }
        }

        res.status(200).json({ message: "File successfully uploaded and email sent", link: downloadLink });
    } catch (error) {
        res.status(500).json({ message: "Error uploading file", error });
    }
});


router.get("/download/:id", async (req, res) => {
    try {
        const file = await File.findOne({
            downloadLink: `https://localhost:5000/api/files/download/${req.params.id}`,
        });

        const password = req.headers['password'];

        if (!file || !file.path || !bcrypt.compareSync(password, file.password)) {
            return res.status(403).send({ message: "Access denied" });
        }

        // Decrypt the file
        const encryptedFileBuffer = fs.readFileSync(file.path);
        const decipher = crypto.createDecipher('aes-256-cbc', password);
        let decrypted = decipher.update(encryptedFileBuffer);
        decrypted = Buffer.concat([decrypted, decipher.final()]);

        const filename = file.originalName || "downloaded_file";
        res.setHeader("Content-Disposition", `attachment; filename="${encodeURIComponent(filename)}"`);
        res.setHeader("Content-Type", file.extension);
        res.end(decrypted);
    } catch (error) {
        res.status(500).send({ message: "Error retrieving file", error: error.message });
    }
});

router.get('/downloadUserFile/:id', authMiddleware, async (req, res) => {
    try {
        const file = await File.findById(req.params.id);
        if (!file) {
            return res.status(404).json({ message: "File not found" });
        }

        // Decrypt the file
        const encryptedFileBuffer = fs.readFileSync(file.path);
        const decipher = crypto.createDecipher('aes-256-cbc', req.user._id.toString());
        let decrypted = decipher.update(encryptedFileBuffer);
        decrypted = Buffer.concat([decrypted, decipher.final()]);

        const filename = file.originalName || "downloaded_file";
        res.setHeader("Content-Disposition", `attachment; filename="${encodeURIComponent(filename)}"`);
        res.setHeader("Content-Type", file.extension);
        res.end(decrypted);
    } catch (error) {
        res.status(500).json({ message: "Error downloading file", error });
    }
});

router.get("/getAllFiles", authMiddleware, async (req, res) => {
    try {
        const files = await File.find({ uploadedBy: req.user._id });
        res.status(200).json({ files });
    } catch (error) {
        res.status(500).json({ message: "Error retrieving files", error });
    }
});

router.delete("/delete/:id", authMiddleware, async (req, res) => {
    try {
        const file = await File.findById(req.params.id);
        if (!file) {
            return res.status(404).json({ message: "File not found" });
        }

        await User.updateOne({ _id: req.user._id }, { $pull: { files: file._id } });

        fs.unlink(file.path, async (err) => {
            if (err) {
                console.error("Error deleting file from filesystem:", err);
                return res.status(500).json({ message: "Error deleting file from filesystem" });
            }
            await File.findByIdAndDelete(file._id);
            res.status(200).json({ message: "File successfully deleted" });
        });
    } catch (error) {
        console.error("Error deleting file:", error);
        res.status(500).json({ message: "Error deleting file", error });
    }
});

module.exports = router;
