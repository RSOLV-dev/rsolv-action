// Simple production RSOLV API for quick deployment
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

// Environment variables
const PORT = process.env.PORT || 3000;
const MASTER_API_KEY = process.env.MASTER_API_KEY || 'rsolv_master_key_' + crypto.randomBytes(16).toString('hex');

// AI Provider Keys (set these in environment)
const AI_PROVIDERS = {
  anthropic: process.env.ANTHROPIC_API_KEY,
  openai: process.env.OPENAI_API_KEY,
  openrouter: process.env.OPENROUTER_API_KEY,
  ollama: 'no-key-needed'
};

// Simple in-memory store for API keys (in production, use a database)
const API_KEYS = {
  // Pre-configured keys
  'rsolv_prod_demo_key': {
    customer_id: 'demo-customer',
    monthly_limit: 10,
    current_usage: 0,
    created_at: new Date()
  }
};

// Generate a new API key for internal use
const INTERNAL_KEY = 'rsolv_internal_' + crypto.randomBytes(16).toString('hex');
API_KEYS[INTERNAL_KEY] = {
  customer_id: 'rsolv-internal',
  monthly_limit: 1000,
  current_usage: 0,
  created_at: new Date()
};

console.log('=== RSOLV API Started ===');
console.log('Internal API Key:', INTERNAL_KEY);
console.log('Demo API Key: rsolv_prod_demo_key');
console.log('Master API Key:', MASTER_API_KEY);

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    service: 'rsolv-api',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

// Credential exchange
app.post('/api/v1/credentials/exchange', (req, res) => {
  const { api_key, providers = ['anthropic'] } = req.body;
  
  if (!api_key || !API_KEYS[api_key]) {
    return res.status(401).json({ error: 'Invalid API key' });
  }
  
  const customer = API_KEYS[api_key];
  
  // Check usage limits
  if (customer.current_usage >= customer.monthly_limit) {
    return res.status(403).json({ error: 'Monthly usage limit exceeded' });
  }
  
  // Generate credentials
  const credentials = {};
  providers.forEach(provider => {
    if (AI_PROVIDERS[provider]) {
      credentials[provider] = {
        api_key: AI_PROVIDERS[provider],
        expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString() // 1 hour
      };
    }
  });
  
  res.json({
    credentials,
    usage: {
      remaining_fixes: customer.monthly_limit - customer.current_usage,
      reset_at: new Date(new Date().setMonth(new Date().getMonth() + 1)).toISOString()
    }
  });
});

// Usage reporting
app.post('/api/v1/usage/report', (req, res) => {
  const { api_key, tokens_used = 0 } = req.body;
  
  if (!api_key || !API_KEYS[api_key]) {
    return res.status(401).json({ error: 'Invalid API key' });
  }
  
  // Update usage (approximate 1 fix per 2000 tokens)
  const fixes_used = Math.ceil(tokens_used / 2000);
  API_KEYS[api_key].current_usage += fixes_used;
  
  console.log(`Usage reported: ${api_key} used ${tokens_used} tokens (${fixes_used} fixes)`);
  
  res.json({ status: 'recorded' });
});

// Admin endpoint to create new API keys
app.post('/api/v1/admin/keys', (req, res) => {
  const { master_key, customer_id, monthly_limit = 100 } = req.body;
  
  if (master_key !== MASTER_API_KEY) {
    return res.status(401).json({ error: 'Invalid master key' });
  }
  
  const new_key = 'rsolv_' + crypto.randomBytes(16).toString('hex');
  API_KEYS[new_key] = {
    customer_id,
    monthly_limit,
    current_usage: 0,
    created_at: new Date()
  };
  
  res.json({ 
    api_key: new_key,
    customer_id,
    monthly_limit
  });
});

// List all keys (admin)
app.get('/api/v1/admin/keys', (req, res) => {
  const { master_key } = req.query;
  
  if (master_key !== MASTER_API_KEY) {
    return res.status(401).json({ error: 'Invalid master key' });
  }
  
  const keys = Object.entries(API_KEYS).map(([key, data]) => ({
    api_key: key,
    ...data
  }));
  
  res.json({ keys });
});

app.listen(PORT, () => {
  console.log(`RSOLV API running on port ${PORT}`);
  console.log('');
  console.log('Environment variables needed:');
  console.log('  ANTHROPIC_API_KEY - Your Anthropic API key');
  console.log('  OPENAI_API_KEY - Your OpenAI API key');
  console.log('  OPENROUTER_API_KEY - Your OpenRouter API key');
  console.log('  MASTER_API_KEY - Admin key for creating new API keys');
});