#!/usr/bin/env bun
// Test AI client directly
import { getAiClient } from './src/ai/client.js';
import { RSOLVCredentialManager } from './src/credentials/manager.js';

async function testAI() {
  console.log('Testing AI client directly...\n');
  
  const credManager = new RSOLVCredentialManager();
  await credManager.initialize('rsolv_prod_demo_key');
  
  const aiClient = await getAiClient({
    provider: 'anthropic',
    model: 'claude-3-sonnet-20240229',
    temperature: 0.2,
    maxTokens: 1000,
    useVendedCredentials: true
  }, credManager);
  
  const testPrompt = `Please respond with a simple code fix in this exact format:

src/test.js:
\`\`\`javascript
console.log('Hello World');
\`\`\`

This is a test of the formatting.`;
  
  try {
    const response = await aiClient.complete(testPrompt, {
      temperature: 0.2,
      maxTokens: 1000
    });
    
    console.log('AI Response:');
    console.log(response);
    console.log('\n---\n');
    
    // Test parsing
    const fileHeaderRegex = /([\w./-]+):\s*```[\w]*\n?([\s\S]*?)```/gm;
    const matches = [...response.matchAll(fileHeaderRegex)];
    
    console.log('Parsed files:', matches.length);
    matches.forEach(match => {
      console.log(`File: ${match[1]}`);
      console.log(`Content preview: ${match[2].substring(0, 50)}...`);
    });
    
  } catch (error) {
    console.error('Error:', error);
  }
}

testAI().catch(console.error);