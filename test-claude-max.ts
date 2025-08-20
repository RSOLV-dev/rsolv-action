import { demonstrateClaudeMax, isClaudeMaxAvailable } from './src/ai/adapters/claude-code-cli-dev.js';

// Run the demonstration
console.log('Starting Claude Code Max demonstration...\n');
demonstrateClaudeMax().then(() => {
  console.log('\nDemo complete!');
}).catch(error => {
  console.error('Demo failed:', error);
});
