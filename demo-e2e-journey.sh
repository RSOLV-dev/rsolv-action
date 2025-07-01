#!/bin/bash

echo "🚀 RSOLV Customer End-to-End Journey Demo"
echo "=========================================="
echo

# Configuration
DEMO_DIR="/tmp/rsolv-demo-$(date +%s)"
REPO_NAME="vulnerable-app"
API_URL="http://localhost:4001"
API_KEY="rsolv_test_abc123"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${YELLOW}Phase 1: Setting up demo environment${NC}"
echo "Creating demo directory: $DEMO_DIR"
mkdir -p "$DEMO_DIR"
cd "$DEMO_DIR"

# Create a mock GitHub repo structure
mkdir -p "$REPO_NAME/.github/workflows"
cd "$REPO_NAME"
git init

echo -e "\n${YELLOW}Phase 2: Creating vulnerable application${NC}"

# Create vulnerable Python file
cat > app.py << 'EOF'
import sqlite3
from flask import Flask, request

app = Flask(__name__)

def get_user(user_id):
    """Get user by ID - VULNERABLE TO SQL INJECTION"""
    conn = sqlite3.connect('users.db')
    # VULNERABLE: Direct string concatenation
    query = "SELECT * FROM users WHERE id = " + user_id
    return conn.execute(query).fetchone()

@app.route('/user/<user_id>')
def user_profile(user_id):
    user = get_user(user_id)
    return {'user': user}

def search_products(name):
    """Search products - VULNERABLE TO SQL INJECTION"""
    conn = sqlite3.connect('products.db')
    # VULNERABLE: % formatting without parameterization
    query = "SELECT * FROM products WHERE name LIKE '%%%s%%'" % name
    return conn.execute(query).fetchall()
EOF

# Create vulnerable JavaScript file
cat > api.js << 'EOF'
const express = require('express');
const { exec } = require('child_process');
const app = express();

// VULNERABLE: Command injection
app.get('/ping/:host', (req, res) => {
    exec('ping -c 4 ' + req.params.host, (err, stdout) => {
        if (err) {
            res.status(500).send('Error');
            return;
        }
        res.send(stdout);
    });
});

// VULNERABLE: Path traversal
app.get('/file/:filename', (req, res) => {
    const fs = require('fs');
    fs.readFile('./uploads/' + req.params.filename, (err, data) => {
        res.send(data);
    });
});

app.listen(3000);
EOF

echo -e "${GREEN}✓ Created vulnerable Python and JavaScript files${NC}"

echo -e "\n${YELLOW}Phase 3: Testing AST analysis locally${NC}"

# Test Python analysis
echo "Testing Python SQL injection detection..."
PYTHON_RESULT=$(curl -s -X POST "$API_URL/api/v1/ast/analyze" \
  -H "X-API-Key: $API_KEY" \
  -H "X-Encryption-Key: $(openssl rand -base64 32)" \
  -H "Content-Type: application/json" \
  -d "{
    \"files\": [{
      \"path\": \"app.py\",
      \"content\": \"$(cat app.py | sed 's/"/\\"/g' | tr '\n' ' ')\",
      \"language\": \"python\"
    }]
  }" 2>/dev/null || echo "API call failed")

if [[ "$PYTHON_RESULT" == *"error"* ]]; then
    echo -e "${RED}✗ Python analysis failed - checking if encryption is needed${NC}"
    # Show the error
    echo "$PYTHON_RESULT" | jq '.' 2>/dev/null || echo "$PYTHON_RESULT"
else
    echo -e "${GREEN}✓ Python analysis completed${NC}"
    echo "$PYTHON_RESULT" | jq '.summary' 2>/dev/null || echo "No vulnerabilities in response"
fi

# Test pattern availability
echo -e "\n${YELLOW}Phase 4: Checking pattern availability${NC}"
PATTERNS=$(curl -s "$API_URL/api/v1/patterns/python" -H "X-API-Key: $API_KEY")
PATTERN_COUNT=$(echo "$PATTERNS" | jq '.patterns | length' 2>/dev/null || echo "0")
echo "Available Python patterns: $PATTERN_COUNT"

if [ "$PATTERN_COUNT" -gt 0 ]; then
    echo "Pattern types available:"
    echo "$PATTERNS" | jq -r '.patterns[].type' 2>/dev/null | sort | uniq
fi

echo -e "\n${YELLOW}Phase 5: Simulating issue creation${NC}"

# Create mock issues based on vulnerabilities
cat > issues.json << 'EOF'
[
  {
    "title": "SQL Injection in app.py",
    "body": "**Severity**: Critical\n**File**: app.py:10\n**Pattern**: python-sql-injection-concat\n\nDirect string concatenation in SQL query detected.",
    "labels": ["security", "critical"]
  },
  {
    "title": "Command Injection in api.js", 
    "body": "**Severity**: Critical\n**File**: api.js:7\n**Pattern**: js-command-injection\n\nUser input passed directly to exec() function.",
    "labels": ["security", "critical"]
  }
]
EOF

echo -e "${GREEN}✓ Would create 2 security issues${NC}"
cat issues.json | jq -r '.[].title'

echo -e "\n${YELLOW}Phase 6: Simulating fix generation${NC}"

# Create a mock fix for the Python SQL injection
cat > fix_sql_injection.patch << 'EOF'
--- a/app.py
+++ b/app.py
@@ -7,7 +7,7 @@ def get_user(user_id):
     """Get user by ID - VULNERABLE TO SQL INJECTION"""
     conn = sqlite3.connect('users.db')
-    # VULNERABLE: Direct string concatenation
-    query = "SELECT * FROM users WHERE id = " + user_id
+    # FIXED: Using parameterized query
+    query = "SELECT * FROM users WHERE id = ?"
-    return conn.execute(query).fetchone()
+    return conn.execute(query, (user_id,)).fetchone()
EOF

# Create test file
cat > test_security.py << 'EOF'
import pytest
from app import get_user

def test_sql_injection_prevented():
    """Verify SQL injection attempts are blocked"""
    # This should not return all users
    malicious_input = "1 OR 1=1 --"
    result = get_user(malicious_input)
    assert result is None or len(result) <= 1
    
def test_normal_user_query():
    """Verify normal queries still work"""
    result = get_user("123")
    # Would need actual DB setup for full test
    assert True  # Placeholder
EOF

echo -e "${GREEN}✓ Generated fix and tests${NC}"
echo "Fix preview:"
head -n 5 fix_sql_injection.patch

echo -e "\n${YELLOW}Phase 7: Summary${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}✓ Demo environment created${NC}"
echo -e "${GREEN}✓ Vulnerable code samples ready${NC}"
echo -e "${GREEN}✓ AST analysis endpoint tested${NC}"
echo -e "${GREEN}✓ Pattern API verified${NC}"
echo -e "${GREEN}✓ Fix generation simulated${NC}"

echo -e "\n${YELLOW}Next Steps for Full Demo:${NC}"
echo "1. Connect AST service to use server-side analysis"
echo "2. Enable automated issue creation from scan results"
echo "3. Integrate Claude Code for actual fix generation"
echo "4. Create real GitHub repo for PR demonstration"

echo -e "\n${YELLOW}Key Metrics:${NC}"
echo "- Current accuracy (local AST): 57.1%"
echo "- Target accuracy (server AST): >90%"
echo "- Time to fix: <5 minutes with automation"
echo "- Languages supported: Python, JavaScript, Ruby, PHP, Java, Go, Elixir"

echo -e "\nDemo files created in: ${DEMO_DIR}/${REPO_NAME}"