# RSOLV Slack Integration Setup

## Overview

The RSOLV Slack integration sends real-time security fix alerts to your team, driving engagement with educational content about each vulnerability fixed.

## Features

- **Real-time Alerts**: Immediate notification when RSOLV fixes a vulnerability
- **Smart Throttling**: Maximum 3 alerts per day per repository to prevent fatigue
- **Business Impact**: Shows potential financial loss prevented
- **One-Click Learning**: Direct links to educational dashboard
- **Engagement Tracking**: Measures click-through rates and learning adoption

## Setup Instructions

### 1. Create Slack Webhook

1. Go to https://api.slack.com/apps
2. Click "Create New App" → "From scratch"
3. Name it "RSOLV Security Alerts"
4. Select your workspace
5. Go to "Incoming Webhooks" → Enable → "Add New Webhook"
6. Select the channel for alerts (e.g., #security or #engineering)
7. Copy the webhook URL

### 2. Configure RSOLV API

Set the environment variable:
```bash
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

Or add to your `.envrc`:
```bash
# RSOLV Slack Integration
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

### 3. Test the Integration

Run the test script:
```bash
cd RSOLV-api
./test_slack_integration.sh
```

You should see a formatted alert in your Slack channel.

## Alert Format

Each alert includes:
- **Severity Level**: 🚨 Critical, 🔴 High, 🟡 Medium, 🟢 Low
- **Vulnerability Type**: SQL Injection, XSS, etc.
- **Business Impact**: Potential financial loss prevented
- **Fix Summary**: What protection was added
- **Learn More**: Link to detailed educational content
- **Team Stats**: Weekly vulnerability fixes and security posture trend

## API Endpoints

### Send Fix Notification
```
POST /api/v1/education/fix-completed
{
  "repo_name": "string",
  "vulnerability": {
    "type": "string",
    "severity": "critical|high|medium|low"
  },
  "fix": {
    "summary": "string"
  },
  "pr_url": "string"
}
```

### Track Engagement
```
GET /api/v1/education/track-click/:alert_id
```

### Get Metrics
```
GET /api/v1/education/metrics?range=day|week|month
```

## Customization

### Adjust Throttle Limits

In `lib/rsolv/notifications/slack_integration.ex`:
```elixir
@max_daily_alerts 3  # Change this value
```

### Customize Alert Format

Modify `format_alert_message/1` in `slack_integration.ex` to change the message structure.

### Add Custom Business Impact Calculations

Update `calculate_business_impact/2` in `education_controller.ex` to add industry-specific calculations.

## Monitoring

View engagement metrics:
```bash
curl http://localhost:4000/api/v1/education/metrics?range=week
```

Response includes:
- Total alerts sent
- Click-through rate
- Most common vulnerability types
- Engagement trends

## Troubleshooting

### No Alerts Showing
1. Check webhook URL is set correctly
2. Verify RSOLV-api is running
3. Check logs: `tail -f log/dev.log`

### Alerts Not Formatting Properly
- Ensure your Slack app has proper permissions
- Try updating to latest Slack Block Kit format

### Throttling Issues
- Check daily count: alerts are limited to 3/day per repo
- Reset throttle for testing in IEx console