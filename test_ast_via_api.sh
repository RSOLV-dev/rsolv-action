#!/bin/bash

echo "🔍 Testing AST Analysis via API"
echo "========================================"

# Generate encryption key
ENCRYPTION_KEY=$(openssl rand -base64 32)
echo "Encryption key: $ENCRYPTION_KEY"

# Create test content
CONTENT='query = "SELECT * FROM users WHERE id = " + user_id'
echo "Test content: $CONTENT"

# Since the API expects encrypted content, let's check the patterns endpoint first
echo -e "\n1. Testing pattern endpoint:"
curl -s http://localhost:4001/api/v1/patterns/python \
  -H "X-API-Key: rsolv_test_abc123" | jq '.patterns | length'

# Check health endpoint
echo -e "\n2. Testing health endpoint:"
curl -s http://localhost:4001/api/health | jq '.'

# Try the security detector endpoint instead
echo -e "\n3. Testing security detector (non-encrypted):"
curl -s -X POST http://localhost:4001/api/v1/security/detect \
  -H "X-API-Key: rsolv_test_abc123" \
  -H "Content-Type: application/json" \
  -d '{
    "files": [{
      "path": "test.py",
      "content": "query = \"SELECT * FROM users WHERE id = \" + user_id",
      "language": "python"
    }]
  }' | jq '.results'