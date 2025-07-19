#!/bin/bash
# RSOLV Demo Repository Creator
# Creates a Node.js app with intentional security vulnerabilities for demonstration

set -e

REPO_NAME=${1:-"vulnerable-demo-app"}
echo "Creating RSOLV demo repository: $REPO_NAME"

# Create directory structure
mkdir -p "$REPO_NAME"
cd "$REPO_NAME"

# Initialize git repo
git init

# Create package.json
cat > package.json << 'EOF'
{
  "name": "vulnerable-demo-app",
  "version": "1.0.0",
  "description": "Demo app with intentional vulnerabilities for RSOLV testing",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "test": "jest"
  },
  "dependencies": {
    "express": "^4.18.2",
    "mysql2": "^3.6.0",
    "ejs": "^3.1.9",
    "bcrypt": "^5.1.0"
  },
  "devDependencies": {
    "jest": "^29.5.0"
  }
}
EOF

# Create main server file
cat > server.js << 'EOF'
const express = require('express');
const mysql = require('mysql2');
const { exec } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.set('view engine', 'ejs');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// VULNERABILITY: Hardcoded database credentials
const dbConfig = {
  host: 'localhost',
  user: 'root',
  password: 'admin123',  // Hardcoded password
  database: 'demo_db'
};

const db = mysql.createConnection(dbConfig);

// Routes
app.use('/api/users', require('./routes/users'));
app.use('/api/search', require('./routes/search'));
app.use('/api/files', require('./routes/files'));
app.use('/api/admin', require('./routes/admin'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
EOF

# Create routes directory
mkdir -p routes

# SQL Injection vulnerability
cat > routes/users.js << 'EOF'
const router = require('express').Router();
const mysql = require('mysql2');

// VULNERABILITY: SQL Injection
router.get('/:id', (req, res) => {
  const userId = req.params.id;
  // Vulnerable to SQL injection - using string concatenation
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// VULNERABILITY: SQL Injection in search
router.get('/search', (req, res) => {
  const { name } = req.query;
  // Another SQL injection - string interpolation
  const query = `SELECT * FROM users WHERE name LIKE '%${name}%'`;
  
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

module.exports = router;
EOF

# XSS vulnerability
cat > routes/search.js << 'EOF'
const router = require('express').Router();

// VULNERABILITY: Cross-Site Scripting (XSS)
router.get('/', (req, res) => {
  const searchTerm = req.query.q || '';
  
  // Rendering user input without escaping
  res.send(`
    <html>
      <body>
        <h1>Search Results</h1>
        <p>You searched for: ${searchTerm}</p>
        <div id="results">
          <!-- User input directly inserted into HTML -->
          <script>
            var term = "${searchTerm}";
            document.getElementById('results').innerHTML = 'Searching for: ' + term;
          </script>
        </div>
      </body>
    </html>
  `);
});

module.exports = router;
EOF

# Path Traversal vulnerability
cat > routes/files.js << 'EOF'
const router = require('express').Router();
const fs = require('fs');
const path = require('path');

// VULNERABILITY: Path Traversal
router.get('/download', (req, res) => {
  const filename = req.query.file;
  
  // No validation of file path - allows directory traversal
  const filePath = path.join(__dirname, '../uploads/', filename);
  
  fs.readFile(filePath, (err, data) => {
    if (err) return res.status(404).send('File not found');
    res.send(data);
  });
});

// VULNERABILITY: Arbitrary File Write
router.post('/upload', (req, res) => {
  const { filename, content } = req.body;
  
  // No validation - allows writing to any location
  const filePath = path.join(__dirname, '../uploads/', filename);
  
  fs.writeFile(filePath, content, (err) => {
    if (err) return res.status(500).send('Upload failed');
    res.send('File uploaded successfully');
  });
});

module.exports = router;
EOF

# Command Injection vulnerability
cat > routes/admin.js << 'EOF'
const router = require('express').Router();
const { exec } = require('child_process');

// VULNERABILITY: Command Injection
router.post('/backup', (req, res) => {
  const { directory } = req.body;
  
  // User input directly passed to shell command
  exec(`tar -czf backup.tar.gz ${directory}`, (err, stdout, stderr) => {
    if (err) return res.status(500).json({ error: stderr });
    res.json({ message: 'Backup completed', output: stdout });
  });
});

// VULNERABILITY: Another Command Injection
router.get('/ping', (req, res) => {
  const host = req.query.host;
  
  // Unsafe command execution
  exec(`ping -c 4 ${host}`, (err, stdout, stderr) => {
    if (err) return res.status(500).json({ error: stderr });
    res.send(`<pre>${stdout}</pre>`);
  });
});

module.exports = router;
EOF

# Create config directory with more vulnerabilities
mkdir -p config

# Hardcoded secrets
cat > config/secrets.js << 'EOF'
// VULNERABILITY: Hardcoded API Keys and Secrets
module.exports = {
  // Hardcoded API keys
  stripeApiKey: 'sk_live_abcdef123456789',
  twilioApiKey: 'AC1234567890abcdef',
  twilioSecret: 'secret123456789',
  
  // Hardcoded JWT secret
  jwtSecret: 'my-super-secret-jwt-key',
  
  // Hardcoded encryption key
  encryptionKey: 'this-is-a-32-char-encryption-key!',
  
  // AWS credentials (never do this!)
  awsAccessKey: 'AKIAIOSFODNN7EXAMPLE',
  awsSecretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
};
EOF

# Weak cryptography
cat > utils/crypto.js << 'EOF'
const crypto = require('crypto');

// VULNERABILITY: Weak Hashing Algorithm
function hashPassword(password) {
  // Using MD5 - cryptographically broken
  return crypto.createHash('md5').update(password).digest('hex');
}

// VULNERABILITY: Insecure Random Number Generation
function generateToken() {
  // Using Math.random() for security-sensitive operation
  return Math.random().toString(36).substring(2);
}

// VULNERABILITY: Weak Encryption
function encrypt(text) {
  // Using deprecated createCipher with weak algorithm
  const cipher = crypto.createCipher('aes128', 'hardcoded-key');
  return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}

module.exports = { hashPassword, generateToken, encrypt };
EOF

# Create views directory for XSS demos
mkdir -p views

# XSS in template
cat > views/profile.ejs << 'EOF'
<!DOCTYPE html>
<html>
<head>
  <title>User Profile</title>
</head>
<body>
  <h1>User Profile</h1>
  
  <!-- VULNERABILITY: XSS - Unescaped user input -->
  <div class="bio">
    <%- userBio %>
  </div>
  
  <!-- VULNERABILITY: XSS in attribute -->
  <img src="<%= userAvatar %>" onerror="<%= userFallback %>">
  
  <!-- VULNERABILITY: DOM XSS -->
  <script>
    var username = '<%- username %>';
    document.write('Welcome, ' + username);
  </script>
</body>
</html>
EOF

# Create a README
cat > README.md << 'EOF'
# Vulnerable Demo App

This application contains intentional security vulnerabilities for testing RSOLV.

## Vulnerabilities Included

1. **SQL Injection** - routes/users.js
2. **Cross-Site Scripting (XSS)** - routes/search.js, views/profile.ejs
3. **Command Injection** - routes/admin.js
4. **Path Traversal** - routes/files.js
5. **Hardcoded Secrets** - config/secrets.js, server.js
6. **Weak Cryptography** - utils/crypto.js
7. **Insecure Random Numbers** - utils/crypto.js

## Setup

```bash
npm install
npm start
```

## Testing with RSOLV

1. Add RSOLV GitHub Action to `.github/workflows/`
2. Run security scan
3. Review created issues
4. Apply `rsolv:automate` label to fix vulnerabilities

**WARNING**: This application is intentionally vulnerable. Do not deploy to production!
EOF

# Create .gitignore
cat > .gitignore << 'EOF'
node_modules/
.env
*.log
.DS_Store
EOF

# Create initial test file
mkdir -p test
cat > test/security.test.js << 'EOF'
// Placeholder for security tests that RSOLV will enhance

describe('Security Tests', () => {
  test('placeholder test', () => {
    expect(true).toBe(true);
  });
});
EOF

# Initialize git and create initial commit
git add .
git commit -m "Initial commit - vulnerable demo app for RSOLV testing"

echo ""
echo "✅ Demo repository created successfully!"
echo ""
echo "Next steps:"
echo "1. cd $REPO_NAME"
echo "2. Create a GitHub repository"
echo "3. git remote add origin https://github.com/YOUR_ORG/$REPO_NAME.git"
echo "4. git push -u origin main"
echo "5. Add RSOLV workflow and API key"
echo "6. Run RSOLV security scan"
echo ""
echo "This demo app contains vulnerabilities in:"
echo "- SQL Injection (routes/users.js)"
echo "- XSS (routes/search.js, views/profile.ejs)"
echo "- Command Injection (routes/admin.js)"
echo "- Path Traversal (routes/files.js)"
echo "- Hardcoded Secrets (config/secrets.js)"
echo "- Weak Crypto (utils/crypto.js)"