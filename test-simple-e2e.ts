#!/usr/bin/env bun
// Simple E2E test
import { getAiClient } from './src/ai/client.js';
import { RSOLVCredentialManager } from './src/credentials/manager.js';

async function test() {
  console.log('NODE_ENV:', process.env.NODE_ENV);
  
  const credManager = new RSOLVCredentialManager();
  await credManager.initialize('rsolv_prod_demo_key');
  
  const aiClient = await getAiClient({
    provider: 'anthropic',
    model: 'claude-3-5-sonnet-20241022',
    temperature: 0.2,
    maxTokens: 1000,
    useVendedCredentials: true
  }, credManager);
  
  const response = await aiClient.complete('What is 2+2? Reply with just the number.', {
    temperature: 0.2,
    maxTokens: 100
  });
  
  console.log('Response:', response);
}

test().catch(console.error);