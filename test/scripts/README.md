# RSOLV API Test Scripts

This directory contains test scripts for validating the RSOLV Educational Framework functionality.

## Available Scripts

### 🔧 `test_webhook_env.sh`
Tests that the Slack webhook URL is properly configured in the environment.
```bash
./test_webhook_env.sh
```

### 📨 `test_direct_slack.exs`
Elixir script that tests direct Slack API communication.
```bash
mix run test_direct_slack.exs
```

### 🚀 `test_end_to_end.sh`
Simulates the complete workflow from RSOLV-action to Slack notification.
```bash
./test_end_to_end.sh
```

### 🚦 `test_throttling.sh`
Verifies that the 3 alerts/day/repository throttling is working correctly.
```bash
./test_throttling.sh
```

### ⚡ `test_slack_integration.sh`
Quick test of the Slack integration by sending a sample notification.
```bash
./test_slack_integration.sh
```

## Prerequisites

1. Ensure the Phoenix server is running:
   ```bash
   cd ../.. && mix phx.server
   ```

2. Set the Slack webhook URL:
   ```bash
   export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
   ```

## Running All Tests

```bash
# Run all tests in sequence
for script in *.sh; do
    echo "Running $script..."
    ./$script
    echo "---"
    sleep 2
done
```

## Expected Results

- ✅ Webhook environment test should show URL is configured
- ✅ Direct Slack test should post a message to your channel
- ✅ End-to-end test should send a formatted security alert
- ✅ Throttling test should allow 3 messages then throttle the 4th
- ✅ Integration test should send a sample fix notification