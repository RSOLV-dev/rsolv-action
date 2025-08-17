# Cache Testing Scripts

This directory contains scripts for testing the false positive caching system.

## Scripts

### Load Testing
- `simple-load-test.sh` - Basic cache performance test
- `false-positive-load-test.sh` - Tests false positive caching specifically
- `programmatic-load-test.sh` - Extended load test with mixed patterns
- `load-test-cache.sh` - Production-like load testing

### Utilities
- `clear-staging-cache.sh` - Clear all cached validations in staging

## Usage

All scripts are configured for staging environment by default:
- API URL: `https://api.rsolv-staging.com`
- API Key: `staging_test_F344F8491174D8F27943D0DB12A4A13D`

### Running Tests

```bash
# Basic cache test
./simple-load-test.sh

# Test false positives specifically
./false-positive-load-test.sh

# Extended load test
./programmatic-load-test.sh

# Clear cache before testing
./clear-staging-cache.sh
```

## Expected Results

- Cache hit rate: >80% for repeated patterns
- Response time: <50ms for cache hits
- False positive detection: 100% accuracy

## Production Testing

Before using in production, update the API_KEY and API_URL variables in each script.