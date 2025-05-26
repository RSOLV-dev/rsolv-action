# Quick Slack Webhook Setup

## 1. Create Slack App (2 minutes)

1. Go to: https://api.slack.com/apps
2. Click "Create New App" → "From scratch"
3. App Name: "RSOLV Security Alerts"
4. Pick your workspace → Create App

## 2. Add Incoming Webhook (1 minute)

1. In the app settings, click "Incoming Webhooks" in left sidebar
2. Toggle "Activate Incoming Webhooks" to ON
3. Click "Add New Webhook to Workspace"
4. Choose channel: #engineering or #security
5. Click "Allow"

## 3. Copy Your Webhook URL

You'll see a URL like:
```
https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX
```

## 4. Set in Terminal

```bash
export SLACK_WEBHOOK_URL="your-webhook-url-here"
```

## 5. Restart Phoenix Server

```bash
# Kill the current server (Ctrl+C twice)
# Then restart:
cd /Users/dylan/dev/rsolv/RSOLV-api
mix phx.server
```

## 6. Test It!

In another terminal:
```bash
cd /Users/dylan/dev/rsolv/RSOLV-api
./test_slack_integration.sh
```

You should see a security alert in your Slack channel!