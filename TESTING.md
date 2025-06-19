# RSOLV-action Testing Guide

## 🧪 Testing Strategy: Local → Staging → Production

### 1. Local Testing with `act`

[nektos/act](https://github.com/nektos/act) runs GitHub Actions locally in Docker.

```bash
# Install act
brew install act

# Test the action locally against staging
./test-local.sh

# Test with specific issue
./test-local.sh 123
```

### 2. Local Testing with `local-action`

[github/local-action](https://github.com/github/local-action) tests the action.yml directly.

```bash
# Install local-action
npm install -g @github/local-action

# Run direct action test
./test-action-locally.sh
```

### 3. Staging Workflow Testing

Test against real staging environment on GitHub:

```bash
# Trigger staging test workflow
gh workflow run staging-test.yml \
  -f api_url="https://api.rsolv-staging.com" \
  -f issue_number="123"
```

### 4. Production Deployment Process

```bash
# 1. Test locally with act
./test-local.sh

# 2. Push to staging branch
git checkout -b staging
git push origin staging

# 3. Test staging workflow
gh workflow run staging-test.yml

# 4. If all tests pass, create release
git tag v1.0.x
git push origin v1.0.x

# 5. Update marketplace listing
gh release create v1.0.x --notes "Release notes"
```

## 🔄 Environment Configuration

### Local Testing
- API URL: `http://localhost:4000` or `https://api.rsolv-staging.com`
- API Key: Use staging key or test key
- Issues: Create test issues with `rsolv:staging-test` label

### Staging
- API URL: `https://api.rsolv-staging.com`
- API Key: `RSOLV_STAGING_API_KEY`
- Branch: `staging` or `main`
- Label: `rsolv:staging-test`

### Production
- API URL: `https://api.rsolv.dev` (default)
- API Key: `RSOLV_API_KEY`
- Branch: Tagged releases (`v1.0.0`)
- Label: `rsolv:automate`

## 🐛 Debugging Tips

### Enable Debug Mode
```yaml
env:
  RSOLV_DEBUG: 'true'
  ACTIONS_STEP_DEBUG: 'true'
```

### Test Specific Scenarios
```bash
# Test error handling
act -s RSOLV_API_KEY="invalid-key" -W .github/workflows/rsolv-dogfood.yml

# Test with different Node versions
act --platform ubuntu-latest=node:18

# Test with specific event payload
act issues -e test-payloads/issue-opened.json
```

### Common Issues
1. **Docker architecture mismatch**: Use `--container-architecture linux/amd64`
2. **Missing secrets**: Set via `-s SECRET_NAME=value`
3. **Network issues**: Use `--network host` for local API testing

## 📊 Test Coverage Checklist

- [ ] Issue detection and filtering
- [ ] API authentication (valid/invalid keys)
- [ ] Staging API connectivity
- [ ] Production API fallback
- [ ] Error handling and retries
- [ ] PR creation workflow
- [ ] Multi-language support
- [ ] Security pattern detection
- [ ] Timeout handling
- [ ] Rate limiting

## 🚀 Benefits of Local Testing

1. **Faster iteration**: No need to push code to test
2. **Cost savings**: No GitHub Actions minutes consumed
3. **Better debugging**: Full local logs and breakpoints
4. **Staging isolation**: Test against staging without affecting production
5. **Reproducible tests**: Consistent environment across team