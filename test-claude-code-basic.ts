#!/usr/bin/env npx tsx

/**
 * Basic test to verify Claude Code SDK works with our API key
 */

import { query } from '@anthropic-ai/claude-code';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function testBasicClaudeCode() {
  console.log('🧪 Testing Claude Code SDK basic functionality...\n');
  
  const testDir = path.join(__dirname, 'claude-code-basic-test');
  
  try {
    // Setup
    await fs.rm(testDir, { recursive: true, force: true }).catch(() => {});
    await fs.mkdir(testDir, { recursive: true });
    
    // Create a simple file
    await fs.writeFile(
      path.join(testDir, 'test.js'),
      'console.log("Hello World");'
    );
    
    console.log('📝 Created test file');
    console.log('🤖 Running Claude Code...\n');
    
    let messageCount = 0;
    let toolCount = 0;
    
    const startTime = Date.now();
    
    for await (const message of query({
      prompt: 'Use the LS tool to list files in the current directory, then use the Read tool to show me what test.js contains.',
      options: {
        cwd: testDir,
        maxTurns: 5,
        verbose: true,
        allowedTools: ['LS', 'Read', 'Grep']
      }
    })) {
      messageCount++;
      
      console.log(`Message ${messageCount} type: ${message.type}`);
      
      // Handle different message types from Claude Code SDK
      if (message.type === 'assistant' && (message as any).message) {
        const assistantMsg = (message as any).message;
        console.log(`  Role: assistant`);
        
        if (assistantMsg.content && Array.isArray(assistantMsg.content)) {
          for (const block of assistantMsg.content) {
            if (block.type === 'tool_use') {
              toolCount++;
              console.log(`  🔧 Tool used: ${block.name}`);
            } else if (block.type === 'text' && block.text) {
              console.log(`  📝 Text: ${block.text.substring(0, 100)}...`);
            }
          }
        }
      } else if (message.type === 'user' && (message as any).message) {
        console.log(`  Tool result from user`);
      } else if (message.type === 'system') {
        console.log(`  System: ${(message as any).subtype || 'unknown'}`);
      } else if (message.type === 'result') {
        console.log(`  Result: ${(message as any).subtype}, duration: ${(message as any).duration_ms}ms`);
      }
    }
    
    const duration = (Date.now() - startTime) / 1000;
    
    console.log(`\n✅ Test completed in ${duration.toFixed(1)}s`);
    console.log(`Messages: ${messageCount}, Tools used: ${toolCount}`);
    
    // Cleanup
    await fs.rm(testDir, { recursive: true, force: true });
    
  } catch (error) {
    console.error('❌ Test failed:', error);
    console.error('\nError details:', {
      name: error.name,
      message: error.message,
      stack: error.stack?.split('\n').slice(0, 5).join('\n')
    });
  }
}

// Set API key and run
if (!process.env.ANTHROPIC_API_KEY) {
  console.error('Please set ANTHROPIC_API_KEY environment variable');
  process.exit(1);
}

testBasicClaudeCode().catch(console.error);