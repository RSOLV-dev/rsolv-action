# RSOLV Webhook Configuration

## Overview
The webhook infrastructure has been successfully implemented to track RSOLV-generated PRs for automated billing.

## Endpoint
- **URL**: https://api.rsolv.dev/webhook/github
- **Method**: POST
- **Headers Required**:
  - `x-github-event`: The GitHub event type (e.g., "pull_request")
  - `x-hub-signature-256`: HMAC signature for webhook verification
  - `Content-Type`: application/json

## Security
The webhook endpoint requires HMAC signature verification. To configure:

1. Set a webhook secret in GitHub when creating the webhook
2. Configure the same secret in the RSOLV API deployment:
   ```bash
   kubectl set env deployment/rsolv-api GITHUB_WEBHOOK_SECRET=your-secret-here
   ```

## Events Handled
- **pull_request**:
  - `opened`: Creates a new fix_attempt record with status "pending"
  - `closed` (with merged=true): Updates fix_attempt status to "merged"
  - `closed` (with merged=false): Updates fix_attempt status to "rejected"

## Database Schema
The `fix_attempts` table tracks all RSOLV-generated PRs:
- `github_org`: Organization name
- `repo_name`: Repository name
- `pr_number`: Pull request number
- `issue_number`: Related issue number (nullable)
- `status`: pending, merged, rejected
- `billing_status`: not_billed, billed, refunded
- `requires_manual_approval`: Boolean (default true during launch)
- `merged_at`: Timestamp when PR was merged

## Testing
Test the webhook locally:
```bash
# Use the test script provided
./test_webhook.sh

# Or manually with curl
curl -X POST https://api.rsolv.dev/webhook/github \
  -H "x-github-event: pull_request" \
  -H "x-hub-signature-256: sha256=YOUR_SIGNATURE" \
  -H "Content-Type: application/json" \
  -d '{"action":"opened","pull_request":{...}}'
```

## Next Steps
1. Configure GITHUB_WEBHOOK_SECRET in production
2. Add webhook URL to GitHub repositories
3. Implement billing approval UI
4. Add webhook retry logic for failed deliveries