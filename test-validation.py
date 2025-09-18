#!/usr/bin/env python3
import requests
import json

# Test AST Validation
validation_payload = {
    "vulnerabilities": [
        {
            "id": "vuln-1",
            "type": "sql-injection",
            "filePath": "routes/users.js",
            "line": 10,
            "code": "query = 'SELECT * FROM users WHERE id = ' + userId",
            "severity": "critical"
        }
    ],
    "files": {
        "routes/users.js": {
            "content": """const express = require('express');
const router = express.Router();

router.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    // Vulnerable SQL injection
    const query = 'SELECT * FROM users WHERE id = ' + userId;
    db.query(query, (err, results) => {
        res.json(results);
    });
});"""
        }
    }
}

response = requests.post(
    "https://api.rsolv.dev/api/v1/vulnerabilities/validate",
    headers={
        "X-Api-Key": "rsolv_-1U3PpIl2T3wo3Nw5v9wB1EM-riNnBcloKtq_gveimc",
        "Content-Type": "application/json"
    },
    json=validation_payload
)

if response.status_code == 200:
    result = response.json()
    print("✅ AST Validation Works!")
    if "stats" in result:
        print(f"  Total: {result['stats'].get('total', 0)}")
        print(f"  Validated: {result['stats'].get('validated', 0)}")
        print(f"  Rejected: {result['stats'].get('rejected', 0)}")
    if "validated" in result and result["validated"]:
        vuln = result["validated"][0]
        print(f"  Vulnerability: {vuln.get('id', 'unknown')}")
        print(f"    Valid: {vuln.get('isValid', False)}")
        print(f"    Confidence: {vuln.get('confidence', 0)}")
else:
    print(f"❌ AST Validation Failed: {response.status_code}")
    print(f"  Response: {response.text[:200]}")