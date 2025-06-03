#!/bin/bash

# Test GitHub webhook with exact format GitHub uses

PAYLOAD='{"action":"opened","number":1,"pull_request":{"id":1,"number":1,"state":"open","title":"Test PR","body":"Test body"}}'
SECRET='iXs+0T2bElP1sd5rUo/qGQKbg6xkf0sLQt/LOEY/254='

# GitHub includes the sha256= prefix in the signature
SIGNATURE="sha256=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" -binary | xxd -p | tr -d '\n')"

echo "Payload: $PAYLOAD"
echo "Secret: $SECRET"
echo "Signature: $SIGNATURE"
echo ""

curl -i -X POST https://api.rsolv.dev/webhook/github \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: pull_request" \
  -H "X-Hub-Signature-256: $SIGNATURE" \
  -d "$PAYLOAD"