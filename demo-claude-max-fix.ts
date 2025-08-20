import { ClaudeCodeMaxAdapter } from './src/ai/adapters/claude-code-cli-dev.js';
import { AIConfig } from './src/ai/types.js';

async function demoClaudeMaxFix() {
  console.log('\n=== Claude Code Max Code Fix Demo ===\n');
  
  // Create a test file with a vulnerability
  const fs = require('fs');
  const testFile = 'test-vulnerable.js';
  
  fs.writeFileSync(testFile, `
// Vulnerable code - using Math.random() for security
function generateToken() {
  return Math.random().toString(36).substring(2);
}

module.exports = { generateToken };
`);
  
  console.log('Created test file with vulnerability:');
  console.log(fs.readFileSync(testFile, 'utf-8'));
  
  // Set up development mode
  process.env.RSOLV_DEV_MODE = 'true';
  
  // Create adapter
  const config: AIConfig = {
    provider: 'claude',
    model: 'claude-3-sonnet',
    temperature: 0.2
  };
  
  const adapter = new ClaudeCodeMaxAdapter(config, process.cwd());
  
  // Create a mock issue context
  const issueContext = {
    title: 'Security: Weak random number generation',
    body: 'Math.random() is not cryptographically secure',
    number: 1,
    labels: ['security'],
    repository: { owner: 'test', name: 'demo' }
  };
  
  const analysis = {
    complexity: 'low',
    relatedFiles: ['test-vulnerable.js'],
    suggestedApproach: 'Replace Math.random() with crypto.randomBytes()'
  };
  
  console.log('\n🔧 Asking Claude Code Max to fix the vulnerability...\n');
  
  const result = await adapter.generateSolution(
    issueContext,
    analysis,
    `Fix the weak cryptography vulnerability in test-vulnerable.js. 
     Replace Math.random() with crypto.randomBytes() for secure token generation.
     Use the Edit tool to modify the file.`
  );
  
  console.log('\n📊 Result:');
  console.log('Success:', result.success);
  console.log('Message:', result.message);
  
  if (result.success) {
    console.log('\n✅ Fixed code:');
    console.log(fs.readFileSync(testFile, 'utf-8'));
  }
  
  // Clean up
  fs.unlinkSync(testFile);
  console.log('\n🧹 Test file cleaned up');
}

// Run the demo
demoClaudeMaxFix().catch(console.error);
