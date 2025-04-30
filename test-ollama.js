#!/usr/bin/env bun
/**
 * Specific test script for the Ollama AI provider
 * 
 * This script tests the Ollama integration with local or remote Ollama servers.
 * 
 * Usage:
 * ```
 * # Test with local Ollama server
 * bun run test-ollama.js
 * 
 * # Test with specific model
 * OLLAMA_MODEL=deepseek-r1:14b bun run test-ollama.js
 * 
 * # Test with remote Ollama server
 * OLLAMA_API_KEY=http://your-server:11434/api:your-token bun run test-ollama.js
 * ```
 */
import { OllamaClient } from './src/ai/providers/ollama';

// Sample issue data
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

async function testOllama(useCliMode = false) {
  console.log('🚀 Testing Ollama AI provider');
  
  // Check if Ollama server is available by attempting to connect
  try {
    const testUrl = process.env.OLLAMA_API_KEY?.split(':')[0] || 'http://localhost:11434';
    const response = await fetch(`${testUrl}/api/version`);
    
    if (!response.ok) {
      throw new Error(`Failed to connect to Ollama server: ${response.status}`);
    }
    
    const version = await response.json();
    console.log(`✅ Connected to Ollama server version: ${version.version}`);
  } catch (error) {
    console.error('❌ Failed to connect to Ollama server:');
    console.error(error.message);
    console.error('\nMake sure Ollama server is running. You can start it with:');
    console.error('  ollama serve');
    console.error('\nIf using a remote Ollama server, make sure the URL is correct in OLLAMA_API_KEY');
    
    // If in CLI mode, exit with error
    if (useCliMode) {
      process.exit(1);
    }
    
    // Otherwise, continue with mock mode
    console.log('\n⚠️ Continuing in mock mode for testing purposes...');
    process.env.NODE_ENV = 'test';
  }
  
  // Use environment variables for configuration or defaults
  const apiKey = process.env.OLLAMA_API_KEY || '';
  const modelName = process.env.OLLAMA_MODEL || 'deepseek-r1:14b';
  
  // Log which model we're using
  if (apiKey.includes(':')) {
    console.log(`Using remote Ollama server with model: ${modelName}`);
  } else {
    console.log(`Using local Ollama server with model: ${modelName}`);
  }
  
  // Create Ollama client
  const config = {
    provider: 'ollama',
    apiKey,
    modelName
  };
  
  const client = new OllamaClient(config);
  
  // Step 1: Analyze issue
  console.log('\nStep 1: Analyzing issue...');
  try {
    const analysis = await client.analyzeIssue(
      sampleIssue.title,
      sampleIssue.body
    );
    
    console.log('\n✅ Analysis complete!');
    console.log(JSON.stringify(analysis, null, 2));
    
    console.log('\nSummary:');
    console.log(`Complexity: ${analysis.complexity}`);
    console.log(`Estimated time: ${analysis.estimatedTime} minutes`);
    console.log(`Recommended approach: ${analysis.recommendedApproach}`);
    
    if (analysis.relatedFiles && analysis.relatedFiles.length > 0) {
      console.log(`Related files: ${analysis.relatedFiles.join(', ')}`);
    }
    
    // Step 2: Generate solution
    console.log('\nStep 2: Generating solution...');
    const solution = await client.generateSolution(
      sampleIssue.title,
      sampleIssue.body,
      analysis
    );
    
    console.log('\n✅ Solution generated!');
    console.log(JSON.stringify(solution, null, 2));
    
    console.log('\nSolution summary:');
    console.log(`Title: ${solution.title}`);
    console.log(`Description: ${solution.description.substring(0, 100)}...`);
    console.log(`Files to change: ${solution.files.length}`);
    if (solution.tests && solution.tests.length > 0) {
      console.log(`Tests: ${solution.tests.length}`);
    }
    
    return { success: true, analysis, solution };
  } catch (error) {
    console.error(`❌ Error during Ollama test:`, error);
    
    if (useCliMode) {
      process.exit(1);
    }
    
    return { success: false, error };
  }
}

// If this file is run directly, execute the test
if (import.meta.main) {
  testOllama(true);
}

export { testOllama };