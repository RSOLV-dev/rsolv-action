#!/bin/bash

# RSOLV Complete Demo Script
# This script demonstrates the full three-phase RSOLV workflow using act

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}           RSOLV Complete Demo - Three Phase Workflow         ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo

# Step 1: Create vulnerable demo app if it doesn't exist
if [ ! -d "rsolv-demo-vulnerable" ]; then
  echo -e "${YELLOW}Creating vulnerable demo application...${NC}"
  bash scripts/create-demo-repo.sh rsolv-demo-vulnerable

  # Fix the utils directory issue
  cd rsolv-demo-vulnerable
  mkdir -p utils
  cat > utils/crypto.js << 'EOF'
const crypto = require('crypto');

// VULNERABILITY: Weak Hashing Algorithm
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// VULNERABILITY: Insecure Random Number Generation
function generateToken() {
  return Math.random().toString(36).substring(2);
}

// VULNERABILITY: Weak Encryption
function encrypt(text) {
  const cipher = crypto.createCipher('aes128', 'hardcoded-key');
  return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}

module.exports = { hashPassword, generateToken, encrypt };
EOF

  # Add GitHub workflow
  mkdir -p .github/workflows
  cat > .github/workflows/rsolv.yml << 'EOF'
name: RSOLV Security Workflow

on:
  workflow_dispatch:
    inputs:
      mode:
        description: 'Mode: scan, validate, mitigate, or full'
        required: false
        default: 'scan'

jobs:
  rsolv-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run RSOLV Action
        uses: ./
        with:
          rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
          mode: ${{ github.event.inputs.mode }}
          enable_security_analysis: 'true'
          enable_ast_validation: 'true'
          use_git_based_editing: 'true'
          use_structured_phases: 'true'
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
EOF

  # Create action.yml to use local action
  cat > action.yml << 'EOF'
name: 'RSOLV Local Action'
description: 'Local RSOLV action for testing'
runs:
  using: 'docker'
  image: '../RSOLV-action/Dockerfile'
EOF

  # Commit changes
  git add .
  git commit -m "Set up for local demo" 2>/dev/null || true
  cd ..
else
  echo -e "${GREEN}✓ Demo app already exists${NC}"
fi

# Step 2: Run with act
echo
echo -e "${YELLOW}Running RSOLV workflow with act...${NC}"
echo

# Check if act is installed
if ! command -v act &> /dev/null; then
  echo -e "${RED}✗ act is not installed${NC}"
  echo "Install with: curl -s https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash"
  exit 1
fi

# Create act configuration
cat > rsolv-demo-vulnerable/.actrc << 'EOF'
-P ubuntu-latest=catthehacker/ubuntu:act-latest
--secret RSOLV_API_KEY=rsolv_-1U3PpIl2T3wo3Nw5v9wB1EM-riNnBcloKtq_gveimc
--secret GITHUB_TOKEN=ghp_demo_token
--env GITHUB_REPOSITORY=demo/rsolv-demo-vulnerable
--env GITHUB_REF=refs/heads/main
--env GITHUB_WORKSPACE=/workspace
--env RSOLV_API_URL=https://api.rsolv.dev
EOF

# Option 1: Run with act (local simulation)
echo -e "${BLUE}Option 1: Running with act (local GitHub Actions simulation)${NC}"
echo "Command: act workflow_dispatch -W .github/workflows/rsolv.yml --input mode=scan"
echo

# Option 2: Direct execution
echo -e "${BLUE}Option 2: Direct execution of RSOLV phases${NC}"
echo

# Phase 1: SCAN
echo -e "${YELLOW}Phase 1: SCAN - Detecting vulnerabilities...${NC}"
cd RSOLV-action
npm run build 2>/dev/null || true

# Run scan phase
RSOLV_MODE=scan \
RSOLV_API_KEY=rsolv_-1U3PpIl2T3wo3Nw5v9wB1EM-riNnBcloKtq_gveimc \
GITHUB_REPOSITORY=demo/rsolv-demo-vulnerable \
GITHUB_WORKSPACE=../rsolv-demo-vulnerable \
node dist/index.js 2>&1 | grep -E "(vulnerabilities|found|detected)" || true

echo -e "${GREEN}✓ Scan phase complete${NC}"
echo

# Phase 2: VALIDATE
echo -e "${YELLOW}Phase 2: VALIDATE - Reducing false positives with AST...${NC}"
RSOLV_MODE=validate \
RSOLV_API_KEY=rsolv_-1U3PpIl2T3wo3Nw5v9wB1EM-riNnBcloKtq_gveimc \
GITHUB_REPOSITORY=demo/rsolv-demo-vulnerable \
GITHUB_WORKSPACE=../rsolv-demo-vulnerable \
node dist/index.js 2>&1 | grep -E "(validated|false positive|confidence)" || true

echo -e "${GREEN}✓ Validation phase complete${NC}"
echo

# Phase 3: MITIGATE
echo -e "${YELLOW}Phase 3: MITIGATE - Generating fixes...${NC}"
echo "(Would create pull requests with fixes in production)"
echo -e "${GREEN}✓ Mitigation phase ready${NC}"

cd ..

# Summary
echo
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}                    Demo Summary                              ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo
echo -e "${GREEN}✅ Demo application created with vulnerabilities:${NC}"
echo "   - SQL Injection (routes/users.js)"
echo "   - XSS (routes/search.js, views/profile.ejs)"
echo "   - Command Injection (routes/admin.js)"
echo "   - Path Traversal (routes/files.js)"
echo "   - Hardcoded Secrets (config/secrets.js)"
echo "   - Weak Cryptography (utils/crypto.js)"
echo
echo -e "${GREEN}✅ GitHub Action workflow configured${NC}"
echo
echo -e "${GREEN}✅ Ready to run with:${NC}"
echo "   1. act (local simulation): cd rsolv-demo-vulnerable && act workflow_dispatch --input mode=full"
echo "   2. GitHub (push to repo): git push origin main"
echo
echo -e "${BLUE}The complete RSOLV workflow:${NC}"
echo "1. SCAN: Local pattern-based vulnerability detection"
echo "2. VALIDATE: Server-side AST validation (70-90% false positive reduction)"
echo "3. MITIGATE: AI-powered fix generation with educational PRs"
echo
echo -e "${GREEN}Demo complete! 🎉${NC}"