#!/usr/bin/env node
// Simple mock RSOLV API server for testing

const http = require('http');
const url = require('url');

const PORT = process.env.PORT || 4000;

// Mock API keys for testing
const VALID_API_KEYS = {
  'rsolv_test_key_123': {
    customer_id: 'test-customer-1',
    monthly_limit: 100,
    current_usage: 0
  },
  'rsolv_dogfood_key': {
    customer_id: 'rsolv-internal',
    monthly_limit: 1000,
    current_usage: 0
  }
};

// Mock AI provider keys (you should set these as env vars)
const AI_CREDENTIALS = {
  anthropic: process.env.ANTHROPIC_API_KEY || 'mock-anthropic-key',
  openai: process.env.OPENAI_API_KEY || 'mock-openai-key',
  openrouter: process.env.OPENROUTER_API_KEY || 'mock-openrouter-key',
  ollama: 'no-key-needed'
};

const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Content-Type', 'application/json');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  // Health check
  if (pathname === '/health' && req.method === 'GET') {
    res.writeHead(200);
    res.end(JSON.stringify({ status: 'ok', service: 'rsolv-api-mock' }));
    return;
  }

  // Credential exchange endpoint
  if (pathname === '/api/v1/credentials/exchange' && req.method === 'POST') {
    let body = '';
    
    req.on('data', chunk => {
      body += chunk.toString();
    });
    
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        const apiKey = data.api_key;
        const providers = data.providers || ['anthropic'];
        
        if (!VALID_API_KEYS[apiKey]) {
          res.writeHead(401);
          res.end(JSON.stringify({ error: 'Invalid API key' }));
          return;
        }
        
        const customer = VALID_API_KEYS[apiKey];
        const credentials = {};
        
        providers.forEach(provider => {
          if (AI_CREDENTIALS[provider]) {
            credentials[provider] = {
              api_key: AI_CREDENTIALS[provider],
              expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString() // 1 hour
            };
          }
        });
        
        res.writeHead(200);
        res.end(JSON.stringify({
          credentials: credentials,
          usage: {
            remaining_fixes: customer.monthly_limit - customer.current_usage,
            reset_at: new Date(new Date().setMonth(new Date().getMonth() + 1)).toISOString()
          }
        }));
      } catch (e) {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
    });
    return;
  }

  // Usage reporting endpoint
  if (pathname === '/api/v1/usage/report' && req.method === 'POST') {
    let body = '';
    
    req.on('data', chunk => {
      body += chunk.toString();
    });
    
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        console.log('Usage reported:', data);
        
        res.writeHead(200);
        res.end(JSON.stringify({ status: 'recorded' }));
      } catch (e) {
        res.writeHead(400);
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
    });
    return;
  }

  // 404 for everything else
  res.writeHead(404);
  res.end(JSON.stringify({ error: 'Not found' }));
});

server.listen(PORT, () => {
  console.log(`Mock RSOLV API server running at http://localhost:${PORT}`);
  console.log('');
  console.log('Available endpoints:');
  console.log('  GET  /health');
  console.log('  POST /api/v1/credentials/exchange');
  console.log('  POST /api/v1/usage/report');
  console.log('');
  console.log('Test API keys:');
  console.log('  - rsolv_test_key_123 (general testing)');
  console.log('  - rsolv_dogfood_key (internal use)');
  console.log('');
  console.log('To use real AI providers, set these environment variables:');
  console.log('  - ANTHROPIC_API_KEY');
  console.log('  - OPENAI_API_KEY'); 
  console.log('  - OPENROUTER_API_KEY');
});