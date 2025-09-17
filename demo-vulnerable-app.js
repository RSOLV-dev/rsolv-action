// Demo Vulnerable Application
// This file contains intentional security vulnerabilities for demonstration purposes

const express = require('express');
const mysql = require('mysql');
const app = express();

// VULNERABILITY 1: SQL Injection
app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    // Vulnerable to SQL injection - user input directly concatenated
    const query = "SELECT * FROM users WHERE id = " + userId;
    db.query(query, (err, result) => {
        res.json(result);
    });
});

// VULNERABILITY 2: Command Injection
app.post('/execute', (req, res) => {
    const userCommand = req.body.command;
    // Vulnerable to command injection - user input passed to eval
    eval(userCommand);
    res.send('Command executed');
});

// VULNERABILITY 3: XSS (Cross-Site Scripting)
app.get('/search', (req, res) => {
    const searchTerm = req.query.q;
    // Vulnerable to XSS - user input rendered without sanitization
    res.send(`<h1>Search results for: ${searchTerm}</h1>`);
});

// VULNERABILITY 4: Path Traversal
app.get('/file', (req, res) => {
    const filename = req.query.name;
    // Vulnerable to path traversal - no validation of file path
    const fs = require('fs');
    fs.readFile('./uploads/' + filename, (err, data) => {
        if (err) return res.status(404).send('File not found');
        res.send(data);
    });
});

// VULNERABILITY 5: Hardcoded Credentials
const API_KEY = "sk-1234567890abcdef";  // Hardcoded API key
const DB_PASSWORD = "admin123";         // Hardcoded database password

// VULNERABILITY 6: Insecure Authentication
app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    // Vulnerable to authentication bypass - weak comparison
    if (username == 'admin' && password == 'password') {
        res.json({ token: 'secret-token-123' });
    }
});

app.listen(3000, () => {
    console.log('Vulnerable demo app running on port 3000');
});