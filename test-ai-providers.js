#!/usr/bin/env bun
/**
 * Simple test script for the AI providers
 */
import { analyzeIssue } from './src/ai/analyzer';

// Sample issue data (no GitHub API calls needed)
const sampleIssue = {
  title: "Fix performance bottleneck in data processing module",
  body: `
## Description
The data processing module is very slow when handling large datasets (>10MB).
Initial profiling suggests the bottleneck is in the sorting algorithm.

## Steps to Reproduce
1. Import a CSV dataset larger than 10MB
2. Run the process() function
3. Observe CPU usage spike and slow response time

## Expected Behavior
Processing should complete within seconds, not minutes.
  `
};

async function main() {
  console.log('🚀 Testing AI providers with sample issue');
  
  // Create issue context
  const issueContext = {
    id: '123',
    source: 'test',
    title: sampleIssue.title,
    body: sampleIssue.body,
    labels: ['bug', 'performance'],
    repository: {
      owner: 'test-owner',
      repo: 'test-repo',
      branch: 'main'
    },
    metadata: {
      htmlUrl: 'https://example.com/issue/123',
      user: 'test-user',
      state: 'open',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    },
    url: 'https://example.com/issue/123'
  };
  
  // For testing purposes, forcing OLLAMA with a mock mode
  // This allows us to test the Ollama integration without having an Ollama server running
  let provider = 'ollama';
  // Use a placeholder URL:TOKEN format to test the remote URL capability
  let apiKey = 'http://example-ollama-server:11434/api:mock-token';
  let modelName = 'llama3';
  
  // Set test mode for the mock data to be returned
  process.env.NODE_ENV = 'test';
  
  // Override based on environment variables if they exist
  if (process.env.AI_PROVIDER) {
    provider = process.env.AI_PROVIDER;
    
    if (provider === 'anthropic' && process.env.ANTHROPIC_API_KEY) {
      apiKey = process.env.ANTHROPIC_API_KEY;
      modelName = process.env.ANTHROPIC_MODEL || 'claude-3-sonnet-20240229';
    } 
    else if (provider === 'ollama' && process.env.OLLAMA_API_KEY) {
      apiKey = process.env.OLLAMA_API_KEY;
      modelName = process.env.OLLAMA_MODEL || 'llama3';
    }
  }
  
  // Create AI config
  const aiConfig = {
    provider,
    apiKey,
    modelName
  };
  
  try {
    console.log(`Using ${provider} provider with model: ${modelName}`);
    console.log('Step 1: Starting issue analysis...');
    const analysis = await analyzeIssue(issueContext, aiConfig);
    
    console.log('\n✅ Analysis complete!');
    console.log(JSON.stringify(analysis, null, 2));
    
    console.log('\nSummary:');
    console.log(`Complexity: ${analysis.complexity}`);
    console.log(`Estimated time: ${analysis.estimatedTime} minutes`);
    console.log(`Recommended approach: ${analysis.recommendedApproach}`);
    
    if (analysis.relatedFiles && analysis.relatedFiles.length > 0) {
      console.log(`Related files: ${analysis.relatedFiles.join(', ')}`);
    }
    
    // Step 2: Generate a solution
    console.log('\nStep 2: Generating solution...');
    
    // For this demo, we'll import the solution generator dynamically
    const { generateSolution } = await import('./src/ai/solution.js');
    
    // Generate the solution
    const solution = await generateSolution(issueContext, analysis, aiConfig);
    
    console.log('\n✅ Solution generated!');
    console.log(JSON.stringify(solution, null, 2));
    
    console.log('\nSolution summary:');
    console.log(`Title: ${solution.title}`);
    console.log(`Description: ${solution.description.substring(0, 100)}...`);
    console.log(`Files to change: ${solution.files.length}`);
    if (solution.tests && solution.tests.length > 0) {
      console.log(`Tests: ${solution.tests.length}`);
    }
    
  } catch (error) {
    console.error(`❌ Error during ${provider} test:`, error);
    
    // Provide additional troubleshooting information
    if (error.message && error.message.includes('not yet implemented')) {
      console.error('\nMake sure you have properly registered the provider in src/ai/client.ts');
    } 
    else if (error.message && error.message.includes('ECONNREFUSED') && provider === 'ollama') {
      console.error('\nMake sure Ollama server is running. You can start it with:');
      console.error('  ollama serve');
      console.error('\nIf using a remote Ollama server, make sure the URL is correct in OLLAMA_API_KEY');
    }
    else if (error.message && error.message.includes('API key')) {
      console.error('\nMake sure you have set the proper environment variable for your provider:');
      console.error('  - For Anthropic: export ANTHROPIC_API_KEY=your_key');
      console.error('  - For OpenRouter: export OPENROUTER_API_KEY=your_key');
      console.error('  - For Ollama: export OLLAMA_API_KEY=your_key (or URL:TOKEN format)');
    }
    
    process.exit(1);
  }
}

main();