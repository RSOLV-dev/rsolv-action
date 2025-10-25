# Load Testing with k6

Load tests for RSOLV billing infrastructure using [k6](https://k6.io/).

## Installation

```bash
# macOS
brew install k6

# Linux
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update
sudo apt-get install k6

# Docker
docker pull grafana/k6:latest
```

## Running Tests

### Signup Load Test (100 concurrent users)
```bash
k6 run load_tests/signup_test.js
```

### Webhook Load Test (1000 webhooks/minute)
```bash
k6 run load_tests/webhook_test.js
```

### API Rate Limit Test (verify 500/hour limit)
```bash
k6 run load_tests/api_rate_limit_test.js
```

### Run All Tests
```bash
for test in load_tests/*.js; do
  echo "Running $test..."
  k6 run "$test"
done
```

## Environment Variables

```bash
export API_BASE_URL=http://localhost:4000
export API_KEY=rsolv_test_key_123
export STRIPE_WEBHOOK_SECRET=whsec_test_secret
```

## Test Thresholds

- **signup_test.js**: 95% requests < 500ms, error rate < 1%
- **webhook_test.js**: 99% requests < 200ms, error rate < 0.1%
- **api_rate_limit_test.js**: Rate limit must trigger at 500 requests/hour

## Monitoring

Results are output to console and can be exported to:
- InfluxDB
- Prometheus
- Grafana Cloud
- JSON/CSV files

See k6 documentation for details.
