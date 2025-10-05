# RFC-059: Local Testing with Act and Claude Code Max

**Status**: APPROVED - Implemented
**Created**: 2025-09-22
**Author**: Dylan
**Updated**: 2025-09-23

## Summary

Enable local testing of RSOLV GitHub Actions workflows using `act` with Claude Code Max to avoid API token consumption during development and testing. Includes comprehensive setup, Docker fixes, and full three-phase testing support.

## Motivation

Testing RSOLV workflows in GitHub Actions consumes API tokens and requires waiting for GitHub infrastructure. By using `act` locally with Claude Code Max, we can:

1. **Save API tokens** - Use local Claude Code Max account instead of API tokens
2. **Faster iteration** - Test changes immediately without pushing to GitHub
3. **Reliable simulation** - Act provides accurate GitHub Actions environment
4. **Offline development** - Test workflows without internet connectivity (after initial setup)

## Design

### Prerequisites

1. **Act Installation**
   ```bash
   # Install act (GitHub Actions local runner)
   curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash
   ```

2. **Full Act Environment** (47.2GB)
   ```bash
   # Pull the full Ubuntu environment for complete compatibility
   docker pull catthehacker/ubuntu:full-latest

   # Configure act to use full environment by default
   mkdir -p ~/.config/act
   echo "-P ubuntu-latest=catthehacker/ubuntu:full-latest" > ~/.config/act/actrc
   ```

3. **Claude Code Max Account**
   - Ensure Claude Code is configured locally at `~/.claude/`
   - This provides unlimited local AI assistance without API tokens

### Workflow Structure

Create workflows that can run both on GitHub and locally with act:

```yaml
name: RSOLV Local Test

on:
  workflow_dispatch:

jobs:
  scan-validate-mitigate:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      issues: write
      pull-requests: write

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Scan for vulnerabilities
        uses: ./RSOLV-action  # Use local action for act
        with:
          mode: scan
          rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
          environment_variables: |
            {
              "RSOLV_TESTING_MODE": "true",
              "CLAUDE_CODE_LOCAL": "true",
              "USE_LOCAL_CLAUDE": "true"
            }

      - name: Validate vulnerabilities
        uses: ./RSOLV-action
        with:
          mode: validate
          rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
          specific_issues: "1036,1037"
          environment_variables: |
            {
              "RSOLV_TESTING_MODE": "true",
              "CLAUDE_CODE_LOCAL": "true",
              "USE_LOCAL_CLAUDE": "true"
            }

      - name: Mitigate vulnerabilities
        uses: ./RSOLV-action
        with:
          mode: mitigate
          rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}
          specific_issues: "1036,1037"
          environment_variables: |
            {
              "RSOLV_TESTING_MODE": "true",
              "CLAUDE_CODE_LOCAL": "true",
              "USE_LOCAL_CLAUDE": "true"
            }
```

### Running with Act

1. **Setup Test Environment**
   ```bash
   # Clone target repository
   cd /tmp
   git clone https://github.com/RSOLV-dev/nodegoat-vulnerability-demo.git
   cd nodegoat-vulnerability-demo

   # Copy RSOLV-action locally (avoids GitHub auth issues)
   cp -r /home/dylan/dev/rsolv/RSOLV-action .
   ```

2. **Create Secrets File** (no API tokens needed)
   ```bash
   cat > .secrets << EOF
   GITHUB_TOKEN=dummy-token-for-local
   RSOLV_API_KEY=dummy-key-for-local
   ANTHROPIC_API_KEY=
   CLAUDE_CODE_API_KEY=
   EOF
   ```

3. **Run Act with Claude Code Mount**
   ```bash
   # Export Claude Code environment variables
   export CLAUDE_CODE_API_KEY=$(cat ~/.claude/claude_code_api_key 2>/dev/null || echo "")
   export ANTHROPIC_API_KEY=$(cat ~/.claude/anthropic_api_key 2>/dev/null || echo "")

   # Run with act using Claude Code Max (no API tokens consumed)
   act workflow_dispatch \
     -W .github/workflows/local-test.yml \
     -P ubuntu-latest=catthehacker/ubuntu:full-latest \
     --secret-file .secrets \
     --bind \
     --pull=false \
     --container-options="-v $HOME/.claude:/root/.claude:ro" \
     --env CLAUDE_CODE_API_KEY=$CLAUDE_CODE_API_KEY \
     --env ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY
   ```

### Key Configuration Points

1. **Environment Variables**
   - `RSOLV_TESTING_MODE=true` - Allows validation in known vulnerable repos
   - `CLAUDE_CODE_LOCAL=true` - Use local Claude Code instead of API
   - `USE_LOCAL_CLAUDE=true` - Force local AI model usage

2. **Container Options**
   - `-v $HOME/.claude:/root/.claude:ro` - Mount Claude Code config read-only
   - `--bind` - Bind mount workspace for file persistence
   - `--pull=false` - Skip pulling images if already present

3. **Action Reference**
   - Use `./RSOLV-action` for local action copy
   - Avoids GitHub authentication issues with private repos

## Implementation

### Phase 1: Basic Setup (Completed)
- ✅ Act installation and configuration
- ✅ Full environment download (47.2GB)
- ✅ Workflow creation for local testing
- ✅ Claude Code mounting configuration

### Phase 2: Validation Persistence (v3.7.45)
- ✅ Fixed ValidationMode to store results with branch reference in test mode
- ✅ Ensures test commits are preserved even in RSOLV_TESTING_MODE

### Phase 3: Docker Git Fix (v3.7.46)
- ✅ Fixed git repository access in Docker-in-Docker environments
- ✅ PhaseDataClient now uses GITHUB_SHA environment variable
- ✅ Falls back gracefully when git is unavailable
- ✅ PR #195 merged

### Phase 4: Documentation
- ✅ This RFC
- ✅ Update CLAUDE.md with act instructions
- ✅ Example workflows in nodegoat-vulnerability-demo

## Benefits

1. **Zero API Token Cost** - Uses local Claude Code Max account
2. **Fast Iteration** - No GitHub Actions queue wait time
3. **Accurate Environment** - Act simulates GitHub Actions precisely
4. **Offline Testing** - Works without internet after initial setup
5. **Debugging** - Direct access to container and logs

## Drawbacks

1. **Large Download** - Full environment is 47.2GB
2. **Docker Required** - Needs Docker Desktop or Docker Engine
3. **Permission Issues** - Act containers may change file ownership
4. **No GitHub API** - Can't access real issues/PRs without token

## Security Considerations

1. **Read-only Mounts** - Claude config mounted read-only
2. **Dummy Tokens** - Use fake tokens for GitHub API
3. **Local Only** - No sensitive data leaves local machine
4. **Container Isolation** - Act runs in isolated Docker containers

## Testing

Test all three phases locally:

```bash
# Full workflow test
cd /tmp/nodegoat-vulnerability-demo
act workflow_dispatch -W .github/workflows/local-test.yml \
  -P ubuntu-latest=catthehacker/ubuntu:full-latest \
  --bind --pull=false \
  --container-options="-v $HOME/.claude:/root/.claude:ro"
```

Expected results:
1. **Scan**: Creates issues for found vulnerabilities
2. **Validate**: Creates branches with failing tests
3. **Mitigate**: Creates branches with fixes and opens PRs

## Troubleshooting

### Issue: Git repository not found in Docker
**Error**: `fatal: not a git repository (or any of the parent directories): .git`

**Solution**: Upgrade to RSOLV-action v3.7.46+ which includes the GITHUB_SHA fix.

### Issue: Slow setup-node action
**Symptom**: Act hangs for 30+ minutes on setup-node

**Solution**: Use `--pull=false` after initial image download and be patient.

### Issue: API authentication failures
**Error**: `401 Unauthorized` from RSOLV API

**Solution**: Verify .secrets file format and API key validity. For local testing, dummy keys work in test mode.

## Real-World Test Results

Successful test run on nodegoat-vulnerability-demo:

1. **SCAN Phase**:
   - Found 143 vulnerabilities (after vendor filtering)
   - Created GitHub issues for tracking
   - Stored phase data successfully

2. **VALIDATE Phase**:
   - Generated RED/GREEN/REFACTOR tests
   - Created branch `rsolv/validate/issue-1036`
   - Committed tests to branch
   - Tests correctly fail on vulnerable code

3. **MITIGATE Phase**:
   - Applied fixes using Claude Code SDK
   - Created branch `rsolv/mitigate/issue-1036`
   - Committed fixes
   - Opened PR with fix summary

## References

- [Act Documentation](https://github.com/nektos/act)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Claude Code Documentation](https://claude.ai/docs)
- [PR #195](https://github.com/RSOLV-dev/rsolv-action/pull/195) - Docker git fix
- RFC-058: Validation test persistence in test mode

## Conclusion

Using act with Claude Code Max provides a robust local testing environment for RSOLV workflows without consuming API tokens. This significantly reduces development costs and improves iteration speed while maintaining full GitHub Actions compatibility.