// Simple test script for the Anthropic AI client
const { execSync } = require('child_process');

// Import from source directly since we're using Bun
const { AnthropicClient } = require('./src/ai/providers/anthropic');

// Check for the API key in the environment
const apiKey = process.env.ANTHROPIC_API_KEY;
if (!apiKey) {
  console.error('ANTHROPIC_API_KEY environment variable is required');
  process.exit(1);
}

// Project should already be built
console.log('Using built project...');

async function main() {
  console.log('Testing Anthropic AI client...');
  
  // Create a config
  const config = {
    provider: 'anthropic',
    apiKey,
    modelName: 'claude-3-sonnet-20240229'
  };
  
  try {
    // Initialize the client
    const client = new AnthropicClient(config);
    console.log('Client initialized successfully');
    
    // Test issue analysis
    const issueTitle = 'Fix error handling in authentication system';
    const issueBody = 'When a user enters special characters in their username, the authentication system fails with a 500 error instead of properly validating and returning a user-friendly message.\n\nSteps to reproduce:\n1. Try to log in with a username containing characters like `<`, `>`, or `&`\n2. System crashes with internal server error\n\nExpected behavior: The system should sanitize inputs and return a proper validation error.';
    
    console.log('\nAnalyzing issue...');
    const analysis = await client.analyzeIssue(issueTitle, issueBody);
    console.log('Analysis result:');
    console.log(JSON.stringify(analysis, null, 2));
    
    console.log('\nGenerating solution...');
    const solution = await client.generateSolution(issueTitle, issueBody, analysis);
    console.log('Solution result:');
    console.log(JSON.stringify(solution, null, 2));
    
  } catch (error) {
    console.error('Error:', error);
  }
}

main();