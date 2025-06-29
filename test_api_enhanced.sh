#!/bin/bash

echo "🔍 Testing Enhanced Pattern API"
echo ""

# Check what's actually being returned
echo "1️⃣ Raw response for enhanced format (no auth):"
curl -s -X GET 'http://localhost:4000/api/v1/patterns?language=javascript&format=enhanced' \
  -H 'Accept: application/json' | python3 -m json.tool 2>&1 | head -50

echo ""
echo "2️⃣ Raw response for standard format (no auth):"
curl -s -X GET 'http://localhost:4000/api/v1/patterns?language=javascript&format=standard' \
  -H 'Accept: application/json' | python3 -m json.tool 2>&1 | head -50

echo ""
echo "3️⃣ Test with made-up API key:"
curl -s -X GET 'http://localhost:4000/api/v1/patterns?language=javascript&format=enhanced' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer test-key-12345' | python3 -m json.tool 2>&1 | head -50

echo ""
echo "✅ Done"