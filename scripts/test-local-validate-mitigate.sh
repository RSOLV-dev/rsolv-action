#!/bin/bash

# Test RSOLV validation and mitigation locally with act

set -e

echo "Setting up local test environment..."

# Check if we're in the nodegoat-vulnerability-demo directory
if [ ! -d "/tmp/nodegoat-vulnerability-demo" ]; then
    echo "Cloning nodegoat-vulnerability-demo to /tmp..."
    git clone https://github.com/RSOLV-dev/nodegoat-vulnerability-demo.git /tmp/nodegoat-vulnerability-demo
fi

cd /tmp/nodegoat-vulnerability-demo

# Copy the latest RSOLV-action code
echo "Copying latest RSOLV-action code..."
rm -rf RSOLV-action
cp -r /home/dylan/dev/rsolv/RSOLV-action .

# Create a local workflow file
cat > .github/workflows/local-test.yml << 'EOF'
name: Local Test - Validate and Mitigate

on:
  push:
    branches: [main]

jobs:
  validate-and-mitigate:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install RSOLV Action dependencies
        run: |
          cd RSOLV-action
          npm install

      - name: Validate Issues
        uses: ./RSOLV-action
        with:
          mode: 'validate'
          github_token: ${{ secrets.GITHUB_TOKEN }}
          environment_variables: |
            {
              "RSOLV_TESTING_MODE": "true",
              "CLAUDE_CODE_API_KEY": "${{ secrets.CLAUDE_CODE_API_KEY }}",
              "ANTHROPIC_API_KEY": "${{ secrets.ANTHROPIC_API_KEY }}"
            }
          specific_issues: '1036,1037'

      - name: Mitigate Issues
        uses: ./RSOLV-action
        with:
          mode: 'mitigate'
          github_token: ${{ secrets.GITHUB_TOKEN }}
          environment_variables: |
            {
              "RSOLV_TESTING_MODE": "true",
              "CLAUDE_CODE_API_KEY": "${{ secrets.CLAUDE_CODE_API_KEY }}",
              "ANTHROPIC_API_KEY": "${{ secrets.ANTHROPIC_API_KEY }}"
            }
          specific_issues: '1036,1037'
EOF

# Create secrets file for act
echo "Creating secrets file..."
cat > .secrets << EOF
GITHUB_TOKEN=${GITHUB_TOKEN}
CLAUDE_CODE_API_KEY=${CLAUDE_CODE_API_KEY}
ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
EOF

echo "Running workflow with act..."
act push --secret-file .secrets -W .github/workflows/local-test.yml

# Clean up
rm -f .secrets

echo "Test complete!"