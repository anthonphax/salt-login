const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();
const db = new sqlite3.Database(":memory:");
const saltRounds = 10; // Bcrypt salt rounds
const MAX_FAILED_ATTEMPTS = 3; // Senha é revogada

// Middleware
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));

// Initialize in-memory database
db.serialize(() => {
    db.run(`
        CREATE TABLE users (
            id INTEGER PRIMARY KEY, 
            username TEXT UNIQUE, 
            password TEXT, 
            revoked INTEGER DEFAULT 0
        )
    `);

    db.run(`
        CREATE TABLE login_attempts (
            id INTEGER PRIMARY KEY, 
            user_id INTEGER, 
            timestamp TEXT, 
            successful INTEGER
        )
    `);
});

// User registration endpoint
app.post("/register", (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: "Username and password are required" });
    }

    // Check if user exists
    db.get(`SELECT id FROM users WHERE username = ?`, [username], (err, user) => {
        if (err) return res.status(500).json({ error: "Database error" });
        if (user) return res.status(409).json({ error: "Username already exists" });

        // Hash the password
        bcrypt.hash(password, saltRounds, (err, hash) => {
            if (err) return res.status(500).json({ error: "Error hashing password" });

            // Insert new user
            db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hash], function (err) {
                if (err) return res.status(500).json({ error: "Database error" });
                res.status(201).json({ message: "User registered successfully!" });
            });
        });
    });
});

// Login endpoint
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: "Username and password are required" });
    }

    // Fetch user data
    db.get(`SELECT id, password, revoked FROM users WHERE username = ?`, [username], (err, user) => {
        if (err) return res.status(500).json({ error: "Database error" });
        if (!user) return res.status(404).json({ error: "User not found" });

        // Check if password is revoked
        if (user.revoked) {
            return res.status(403).json({ error: "Password revoked. Please reset your password." });
        }

        // Verify password
        bcrypt.compare(password, user.password, (err, result) => {
            if (err) return res.status(500).json({ error: "Error verifying password" });

            const successful = result ? 1 : 0;

            // Log login attempt
            db.run(
                `INSERT INTO login_attempts (user_id, timestamp, successful) VALUES (?, datetime('now'), ?)`,
                [user.id, successful],
                () => {
                    if (successful) {
                        res.status(200).json({ message: "Login successful" });
                    } else {
                        // Check failed attempts in the last hour
                        db.get(
                            `SELECT COUNT(*) AS failed_attempts FROM login_attempts 
                            WHERE user_id = ? AND successful = 0 AND timestamp >= datetime('now', '-1 hour')`,
                            [user.id],
                            (err, result) => {
                                if (err) return res.status(500).json({ error: "Database error" });

                                if (result.failed_attempts >= MAX_FAILED_ATTEMPTS) {
                                    // Revoke password
                                    db.run(`UPDATE users SET revoked = 1 WHERE id = ?`, [user.id], () => {
                                        res.status(403).json({
                                            error: "Too many failed attempts. Password revoked."
                                        });
                                    });
                                } else {
                                    res.status(401).json({ error: "Incorrect password" });
                                }
                            }
                        );
                    }
                }
            );
        });
    });
});

// Password reset endpoint
app.post("/reset-password", (req, res) => {
    const { username, newPassword } = req.body;

    if (!username || !newPassword) {
        return res.status(400).json({ error: "Username and new password are required" });
    }

    // Hash the new password
    bcrypt.hash(newPassword, saltRounds, (err, hash) => {
        if (err) return res.status(500).json({ error: "Error hashing new password" });

        // Update user password and reset revoked status
        db.run(
            `UPDATE users SET password = ?, revoked = 0 WHERE username = ?`,
            [hash, username],
            function (err) {
                if (err) return res.status(500).json({ error: "Database error" });
                if (this.changes === 0) return res.status(404).json({ error: "User not found" });
                res.status(200).json({ message: "Password reset successfully!" });
            }
        );
    });
});

// Serve frontend
app.get("*", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Start the server
app.listen(3000, () => {
    console.log("Server running on http://localhost:3000");
});
