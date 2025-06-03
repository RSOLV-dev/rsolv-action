#!/bin/bash

# Test with the exact same secret GitHub should be using
PAYLOAD='{"zen":"Design for failure.","hook_id":123}'
SECRET='iXs+0T2bElP1sd5rUo/qGQKbg6xkf0sLQt/LOEY/254='

# Compute signature exactly as GitHub does
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" -binary | xxd -p | tr -d '\n')

echo "Testing webhook with ping event..."
echo "Payload: $PAYLOAD"
echo "Signature: sha256=$SIGNATURE"
echo ""

curl -i -X POST https://api.rsolv.dev/webhook/github \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: ping" \
  -H "X-Hub-Signature-256: sha256=$SIGNATURE" \
  -d "$PAYLOAD"