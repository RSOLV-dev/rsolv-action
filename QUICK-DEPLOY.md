# Quick Deploy Guide for RSOLV API

This guide shows how to quickly deploy the RSOLV API for testing and dogfooding.

## Option 1: Deploy to Railway (Recommended)

1. **Install Railway CLI**:
   ```bash
   brew install railway
   ```

2. **Login to Railway**:
   ```bash
   railway login
   ```

3. **Initialize and Deploy**:
   ```bash
   cd RSOLV-api
   railway init
   railway up
   ```

4. **Set Environment Variables**:
   ```bash
   railway vars set ANTHROPIC_API_KEY="your-anthropic-key"
   railway vars set OPENROUTER_API_KEY="your-openrouter-key"
   railway vars set MASTER_API_KEY="your-secure-master-key"
   ```

5. **Get your API URL**:
   ```bash
   railway open
   ```

## Option 2: Deploy to Render

1. Go to https://render.com
2. Create a new Web Service
3. Connect your GitHub repo
4. Set environment variables in the dashboard
5. Deploy!

## Option 3: Deploy to Vercel

1. **Install Vercel CLI**:
   ```bash
   npm i -g vercel
   ```

2. **Deploy**:
   ```bash
   cd RSOLV-api
   vercel
   ```

3. **Set Environment Variables**:
   ```bash
   vercel env add ANTHROPIC_API_KEY
   vercel env add OPENROUTER_API_KEY
   vercel env add MASTER_API_KEY
   ```

## After Deployment

1. **Test the API**:
   ```bash
   curl https://your-api-url/health
   ```

2. **Get Internal API Key**:
   Check the deployment logs for the internal API key that was generated.

3. **Update GitHub Secrets**:
   ```bash
   gh secret set RSOLV_API_KEY --body "your-internal-api-key" --repo RSOLV-dev/rsolv-action
   gh secret set RSOLV_API_URL --body "https://your-api-url" --repo RSOLV-dev/rsolv-action
   ```

4. **Test Dogfooding**:
   ```bash
   gh workflow run rsolv-dogfood.yml
   ```

## Managing API Keys

Create new API keys using the admin endpoint:

```bash
curl -X POST https://your-api-url/api/v1/admin/keys \
  -H "Content-Type: application/json" \
  -d '{
    "master_key": "your-master-key",
    "customer_id": "test-customer",
    "monthly_limit": 100
  }'
```

List all API keys:

```bash
curl "https://your-api-url/api/v1/admin/keys?master_key=your-master-key"
```