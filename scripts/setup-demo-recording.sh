#!/bin/bash
# RSOLV Demo Video Recording Setup Script

set -e

echo "🎬 RSOLV Demo Video Recording Setup"
echo "===================================="

# Check prerequisites
if [ -z "$GITHUB_TOKEN" ]; then
    echo "❌ Error: GITHUB_TOKEN not set"
    echo "Please run: export GITHUB_TOKEN=your_github_token"
    exit 1
fi

# Setup demo directory
DEMO_DIR="$HOME/demo/rsolv-sql-injection-demo"
echo "📁 Setting up demo directory at $DEMO_DIR"

if [ -d "$DEMO_DIR" ]; then
    echo "⚠️  Demo directory already exists. Remove it? (y/n)"
    read -r response
    if [ "$response" = "y" ]; then
        rm -rf "$DEMO_DIR"
    else
        echo "Please remove or rename the existing directory first."
        exit 1
    fi
fi

mkdir -p "$DEMO_DIR"
cd "$DEMO_DIR"

# Initialize git repo
echo "🔧 Initializing git repository..."
git init
git config user.name "Demo User"
git config user.email "demo@rsolv.dev"

# Create vulnerable code
echo "💉 Creating vulnerable authentication code..."
mkdir -p src/auth
cat > src/auth/login.js << 'EOF'
const mysql = require('mysql');
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password',
  database: 'ecommerce'
});

// VULNERABLE: Direct string concatenation allows SQL injection
function authenticateUser(username, password) {
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  
  return new Promise((resolve, reject) => {
    connection.query(query, (error, results) => {
      if (error) reject(error);
      resolve(results.length > 0 ? results[0] : null);
    });
  });
}

// Additional vulnerable endpoint
function getUserOrders(userId) {
  // VULNERABLE: No input validation
  const query = `SELECT * FROM orders WHERE user_id = ${userId}`;
  
  return new Promise((resolve, reject) => {
    connection.query(query, (error, results) => {
      if (error) reject(error);
      resolve(results);
    });
  });
}

module.exports = { authenticateUser, getUserOrders };
EOF

# Create package.json
echo "📦 Creating package.json..."
cat > package.json << 'EOF'
{
  "name": "demo-ecommerce",
  "version": "1.0.0",
  "description": "E-commerce platform with authentication",
  "main": "index.js",
  "dependencies": {
    "mysql": "^2.18.1",
    "express": "^4.18.2"
  }
}
EOF

# Create README
echo "📝 Creating README..."
cat > README.md << 'EOF'
# Demo E-commerce Platform

This is a demo e-commerce platform processing $10M in daily transactions.

## Security Notice
Our security team has identified potential vulnerabilities that need immediate attention.

## Setup
```bash
npm install
npm start
```
EOF

# Commit the code
echo "💾 Committing vulnerable code..."
git add .
git commit -m "Initial authentication system for e-commerce platform"

echo ""
echo "✅ Demo repository created successfully!"
echo ""
echo "📋 Next steps:"
echo "1. Create a new GitHub repository named 'demo-ecommerce-security'"
echo "2. Run these commands to push:"
echo ""
echo "   cd $DEMO_DIR"
echo "   git remote add origin https://github.com/YOUR_USERNAME/demo-ecommerce-security.git"
echo "   git push -u origin main"
echo ""
echo "3. Create an issue with this content:"
echo ""
cat << 'EOF'
Title: Critical: Security audit needed for authentication system

Our security team has flagged potential vulnerabilities in our authentication system. 
We need to review and fix any SQL injection vulnerabilities in the login flow.

This is critical as we process over $10M in daily transactions and any breach 
could result in significant financial and reputational damage.

Priority: CRITICAL
Labels: security, high-priority, bug
EOF
echo ""
echo "4. Copy the issue URL for the demo"
echo ""
echo "🎬 Ready to record!"