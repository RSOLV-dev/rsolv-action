#!/usr/bin/env bun
/**
 * Test Claude Code with longer timeout to see if we get actual responses
 */

import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';

interface TestConfig {
  timeout: number;
  verbose: boolean;
  outputFormat: 'text' | 'json' | 'stream-json';
}

async function testClaudeCodeWithLongTimeout(config: TestConfig) {
  console.log(`Testing Claude Code with ${config.timeout/1000}s timeout...`);
  
  // Get vended credentials first
  let apiKey = process.env.ANTHROPIC_API_KEY;
  
  if (!apiKey) {
    console.log('No ANTHROPIC_API_KEY found, trying vended credentials...');
    try {
      const { RSOLVCredentialManager } = await import('./src/credentials/manager.js');
      const rsolvApiKey = process.env.RSOLV_INTERNAL_API_KEY || process.env.RSOLV_API_KEY;
      
      if (!rsolvApiKey) {
        console.error('❌ No RSOLV_API_KEY found in environment');
        return;
      }
      
      const manager = new RSOLVCredentialManager(rsolvApiKey, 'https://api.rsolv.dev');
      await manager.initialize();
      apiKey = await manager.getCredential('anthropic');
      console.log('✅ Got vended credentials');
    } catch (error) {
      console.error('❌ Failed to get vended credentials:', error);
      return;
    }
  }
  
  const prompt = `Analyze this security vulnerability:

ISSUE: Login endpoint vulnerable to timing attack
DESCRIPTION: The /api/auth/login endpoint in src/auth/login.js doesn't implement constant-time comparison for passwords, making it vulnerable to timing attacks.

An attacker could potentially determine valid passwords by measuring response times.

The password comparison on line 15 uses regular string comparison which returns early on first mismatch.

Please provide:
1. A description of the vulnerability
2. The specific file and line that needs to be fixed  
3. The exact code change needed
4. An explanation of why this fix prevents timing attacks

Please be specific about the file path and code changes.`;

  const args = ['--print'];
  
  if (config.verbose) {
    args.push('--verbose');
  }
  
  args.push('--output-format', config.outputFormat);
  
  if (!apiKey) {
    console.error('No API key available');
    return;
  }
  
  console.log('Command:', 'claude', args.join(' '));
  console.log('Prompt length:', prompt.length, 'chars');
  
  const startTime = Date.now();
  
  return new Promise<void>((resolve, reject) => {
    const childProcess = spawn('claude', args, {
      cwd: process.cwd(),
      shell: false,
      env: {
        ...process.env,
        ANTHROPIC_API_KEY: apiKey
      },
      stdio: ['pipe', 'pipe', 'pipe']
    });
    
    let output = '';
    let errorOutput = '';
    let chunkCount = 0;
    
    // Set up timeout
    const timeout = setTimeout(() => {
      console.log(`\n❌ TIMEOUT after ${config.timeout/1000}s`);
      console.log(`Received ${chunkCount} chunks, ${output.length} chars total`);
      if (output.length > 0) {
        console.log('Partial output:', output.substring(0, 500));
      }
      childProcess.kill('SIGTERM');
      reject(new Error(`Timeout after ${config.timeout/1000}s`));
    }, config.timeout);
    
    childProcess.stdout.on('data', (data) => {
      const chunk = data.toString();
      output += chunk;
      chunkCount++;
      
      const elapsed = Date.now() - startTime;
      console.log(`📥 Chunk ${chunkCount} after ${elapsed}ms: ${chunk.length} chars`);
      
      // Show first 100 chars of each chunk for debugging
      if (chunk.length > 0) {
        console.log(`   Preview: ${chunk.substring(0, 100).replace(/\n/g, '\\n')}`);
      }
    });
    
    childProcess.stderr.on('data', (data) => {
      errorOutput += data.toString();
      console.log(`🚨 Error chunk: ${data.toString()}`);
    });
    
    childProcess.on('close', (code) => {
      clearTimeout(timeout);
      const elapsed = Date.now() - startTime;
      
      console.log(`\n✅ Process completed in ${elapsed}ms with code ${code}`);
      console.log(`Total chunks: ${chunkCount}`);
      console.log(`Output length: ${output.length} chars`);
      console.log(`Error length: ${errorOutput.length} chars`);
      
      if (output.length > 0) {
        console.log('\n📄 FULL OUTPUT:');
        console.log('=' .repeat(80));
        console.log(output);
        console.log('=' .repeat(80));
      }
      
      if (errorOutput.length > 0) {
        console.log('\n🚨 ERROR OUTPUT:');
        console.log('-'.repeat(80));
        console.log(errorOutput);
        console.log('-'.repeat(80));
      }
      
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`Process exited with code ${code}`));
      }
    });
    
    childProcess.on('error', (error) => {
      clearTimeout(timeout);
      console.log(`\n💥 Process error: ${error.message}`);
      reject(error);
    });
    
    // Write prompt to stdin
    console.log('📝 Writing prompt to stdin...');
    childProcess.stdin.write(prompt);
    childProcess.stdin.end();
    console.log('✅ Prompt sent, waiting for response...');
  });
}

async function runTests() {
  console.log('🧪 Testing Claude Code CLI with various timeout settings\n');
  
  const configs: TestConfig[] = [
    { timeout: 10 * 60 * 1000, verbose: true, outputFormat: 'text' },       // 10 minutes, verbose, text
    { timeout: 10 * 60 * 1000, verbose: true, outputFormat: 'json' },       // 10 minutes, verbose, json
    { timeout: 10 * 60 * 1000, verbose: false, outputFormat: 'text' },      // 10 minutes, no verbose, text
  ];
  
  for (let i = 0; i < configs.length; i++) {
    const config = configs[i];
    console.log(`\n${'='.repeat(80)}`);
    console.log(`TEST ${i + 1}/${configs.length}: ${config.outputFormat} format, verbose: ${config.verbose}`);
    console.log(`${'='.repeat(80)}`);
    
    try {
      await testClaudeCodeWithLongTimeout(config);
      console.log(`✅ Test ${i + 1} completed successfully`);
      break; // If one succeeds, no need to try others
    } catch (error) {
      console.log(`❌ Test ${i + 1} failed: ${error instanceof Error ? error.message : String(error)}`);
      
      if (i === configs.length - 1) {
        console.log('\n💔 All tests failed');
      } else {
        console.log('\n🔄 Trying next configuration...');
      }
    }
  }
}

// Run the tests
if (import.meta.main) {
  runTests().catch(console.error);
}