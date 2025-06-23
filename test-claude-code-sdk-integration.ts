#!/usr/bin/env npx tsx

/**
 * Test Claude Code TypeScript SDK integration with tool monitoring
 * This validates that the SDK is properly using Edit/MultiEdit tools
 * for in-place vulnerability fixes
 */

import { query, type SDKMessage } from '@anthropic-ai/claude-code';
import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';

const execAsync = promisify(exec);

interface ToolUsageMetrics {
  Read: number;
  Write: number;
  Edit: number;
  MultiEdit: number;
  Bash: number;
  Grep: number;
  total: number;
  toolCalls: Array<{
    tool: string;
    timestamp: number;
    input?: any;
  }>;
}

interface TestResult {
  success: boolean;
  vulnerabilityType: string;
  toolMetrics: ToolUsageMetrics;
  fileChanges: {
    modified: number;
    created: number;
    deleted: number;
  };
  fixValidated: boolean;
  duration: number;
  messages: number;
}

async function setupTestRepo(vulnerabilityType: string): Promise<{ repoPath: string; fileName: string }> {
  const repoPath = path.join(process.cwd(), 'test-claude-sdk-repo');
  
  // Clean up if exists
  try {
    await execAsync(`rm -rf ${repoPath}`);
  } catch {}
  
  await fs.mkdir(repoPath, { recursive: true });
  
  // Initialize git repo
  await execAsync('git init', { cwd: repoPath });
  await execAsync('git config user.name "RSOLV Test"', { cwd: repoPath });
  await execAsync('git config user.email "test@rsolv.ai"', { cwd: repoPath });
  
  let fileName: string;
  let content: string;
  
  switch (vulnerabilityType) {
    case 'sql-injection':
      fileName = 'app.js';
      content = `const express = require('express');
const mysql = require('mysql2');

const app = express();

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  // VULNERABLE: SQL injection through string concatenation
  const query = "SELECT * FROM users WHERE id = " + userId;
  
  db.query(query, (err, results) => {
    if (err) {
      console.error('Database error:', err);
      res.status(500).send('Internal server error');
    } else {
      res.json(results);
    }
  });
});

app.delete('/user/:id', (req, res) => {
  const userId = req.params.id;
  // VULNERABLE: Another SQL injection
  const deleteQuery = \`DELETE FROM users WHERE id = \${userId}\`;
  
  db.query(deleteQuery, (err) => {
    if (err) {
      res.status(500).send('Error deleting user');
    } else {
      res.json({ message: 'User deleted' });
    }
  });
});`;
      break;
      
    case 'xss':
      fileName = 'template.js';
      content = `function renderUserProfile(user) {
  // VULNERABLE: Direct HTML injection without escaping
  return \`
    <div class="user-profile">
      <h1>Welcome \${user.name}</h1>
      <p>Bio: \${user.bio}</p>
      <div class="about">
        \${user.about}
      </div>
    </div>
  \`;
}

function renderComment(comment) {
  // VULNERABLE: Another XSS vulnerability
  return '<div class="comment">' + comment.text + '</div>';
}

module.exports = { renderUserProfile, renderComment };`;
      break;
      
    default:
      throw new Error(`Unknown vulnerability type: ${vulnerabilityType}`);
  }
  
  await fs.writeFile(path.join(repoPath, fileName), content);
  await execAsync(`git add ${fileName}`, { cwd: repoPath });
  await execAsync('git commit -m "Add vulnerable code"', { cwd: repoPath });
  
  return { repoPath, fileName };
}

async function runClaudeCodeSDK(
  repoPath: string, 
  fileName: string, 
  vulnerabilityType: string
): Promise<{ metrics: ToolUsageMetrics; messages: SDKMessage[] }> {
  const metrics: ToolUsageMetrics = {
    Read: 0,
    Write: 0,
    Edit: 0,
    MultiEdit: 0,
    Bash: 0,
    Grep: 0,
    total: 0,
    toolCalls: []
  };
  
  const messages: SDKMessage[] = [];
  
  const prompt = `You are fixing security vulnerabilities. Fix the ${vulnerabilityType} vulnerability in ${fileName}.

CRITICAL INSTRUCTIONS:
1. Use the Edit or MultiEdit tools to modify the existing file
2. Do NOT create new files - only edit the existing vulnerable file
3. Make minimal, surgical changes to fix the security issue
4. Preserve all functionality while fixing the vulnerability

For SQL injection: Replace string concatenation with parameterized queries
For XSS: Add proper HTML escaping or use safe rendering methods

After fixing, provide a brief summary of what you changed.`;

  console.log('🤖 Running Claude Code SDK...\n');
  
  for await (const message of query({
    prompt,
    options: {
      cwd: repoPath,
      maxTurns: 10,
      // These tools are most relevant for our use case
      allowedTools: ['Read', 'Edit', 'MultiEdit', 'Grep', 'Bash'],
      verboseLogging: true
    }
  })) {
    messages.push(message);
    
    // Process assistant messages to track tool usage
    if (message.type === 'message' && (message as any).role === 'assistant') {
      const assistantMsg = message as any;
      if (assistantMsg.content && Array.isArray(assistantMsg.content)) {
        for (const block of assistantMsg.content) {
          if (block.type === 'tool_use' && block.name) {
            metrics.total++;
            const toolName = block.name;
            if (toolName in metrics) {
              metrics[toolName as keyof typeof metrics]++;
            }
            metrics.toolCalls.push({
              tool: toolName,
              timestamp: Date.now(),
              input: block.input
            });
            
            console.log(`📦 Tool used: ${toolName}`);
            
            // Log Edit/MultiEdit details
            if ((toolName === 'Edit' || toolName === 'MultiEdit') && block.input) {
              console.log(`   File: ${block.input.file_path || block.input.path || 'unknown'}`);
            }
          }
        }
      }
    }
    
    // Show text responses
    if (message.type === 'text' && (message as any).text) {
      const text = (message as any).text;
      console.log('\nClaude:', text.substring(0, 200) + (text.length > 200 ? '...' : ''));
    }
  }
  
  return { metrics, messages };
}

async function validateFix(
  repoPath: string, 
  vulnerabilityType: string
): Promise<{ fileChanges: TestResult['fileChanges']; fixValidated: boolean }> {
  // Get git status
  const { stdout: statusOutput } = await execAsync('git status --porcelain', { cwd: repoPath });
  const statusLines = statusOutput.split('\n').filter(line => line.trim());
  
  const fileChanges = {
    modified: statusLines.filter(l => l.startsWith(' M')).length,
    created: statusLines.filter(l => l.startsWith('??')).length,
    deleted: statusLines.filter(l => l.startsWith(' D')).length
  };
  
  // Get diff to validate fix
  const { stdout: diffOutput } = await execAsync('git diff', { cwd: repoPath });
  
  let fixValidated = false;
  
  switch (vulnerabilityType) {
    case 'sql-injection':
      // Check for parameterized queries
      fixValidated = diffOutput.includes('?') || 
                    diffOutput.includes('parameterized') ||
                    diffOutput.includes('prepared statement') ||
                    diffOutput.includes('[userId]');
      break;
      
    case 'xss':
      // Check for escaping functions
      fixValidated = diffOutput.includes('escape') ||
                    diffOutput.includes('sanitize') ||
                    diffOutput.includes('encode') ||
                    diffOutput.includes('textContent') ||
                    diffOutput.includes('DOMPurify');
      break;
  }
  
  return { fileChanges, fixValidated };
}

async function runTest(vulnerabilityType: string): Promise<TestResult> {
  console.log(`\n🧪 Testing ${vulnerabilityType} fix with Claude Code SDK\n`);
  
  const startTime = Date.now();
  
  try {
    // Setup test repository
    const { repoPath, fileName } = await setupTestRepo(vulnerabilityType);
    console.log(`✅ Created test repo with vulnerable ${fileName}\n`);
    
    // Run Claude Code SDK
    const { metrics, messages } = await runClaudeCodeSDK(repoPath, fileName, vulnerabilityType);
    
    // Validate the fix
    const { fileChanges, fixValidated } = await validateFix(repoPath, vulnerabilityType);
    
    const duration = (Date.now() - startTime) / 1000;
    
    // Calculate success
    const editRatio = (metrics.Edit + metrics.MultiEdit) / Math.max(1, metrics.total);
    const success = fileChanges.created === 0 && fixValidated && editRatio >= 0.5;
    
    // Print results
    console.log('\n📊 Test Results:');
    console.log('================');
    console.log(`Duration: ${duration.toFixed(1)}s`);
    console.log(`Total messages: ${messages.length}`);
    console.log(`Total tool calls: ${metrics.total}`);
    console.log('\nTool usage breakdown:');
    console.log(`  Read: ${metrics.Read}`);
    console.log(`  Edit: ${metrics.Edit}`);
    console.log(`  MultiEdit: ${metrics.MultiEdit}`);
    console.log(`  Write: ${metrics.Write}`);
    console.log(`  Other: ${metrics.Bash + metrics.Grep}`);
    console.log(`\nEdit tool ratio: ${(editRatio * 100).toFixed(1)}%`);
    console.log('\nFile changes:');
    console.log(`  Modified: ${fileChanges.modified}`);
    console.log(`  Created: ${fileChanges.created}`);
    console.log(`  Deleted: ${fileChanges.deleted}`);
    console.log(`\nValidation:`);
    console.log(`  In-place editing: ${fileChanges.created === 0 ? '✅ PASS' : '❌ FAIL'}`);
    console.log(`  Edit tool usage: ${editRatio >= 0.5 ? '✅ PASS' : '❌ FAIL'}`);
    console.log(`  Fix validated: ${fixValidated ? '✅ PASS' : '❌ FAIL'}`);
    console.log(`\nOverall: ${success ? '✅ PASS' : '❌ FAIL'}`);
    
    // Show the actual changes
    if (fileChanges.modified > 0) {
      console.log('\n📝 Git diff preview:');
      const { stdout: diff } = await execAsync('git diff --stat', { cwd: repoPath });
      console.log(diff);
    }
    
    // Cleanup
    await execAsync(`rm -rf ${repoPath}`);
    
    return {
      success,
      vulnerabilityType,
      toolMetrics: metrics,
      fileChanges,
      fixValidated,
      duration,
      messages: messages.length
    };
    
  } catch (error) {
    console.error('❌ Test failed:', error);
    return {
      success: false,
      vulnerabilityType,
      toolMetrics: {
        Read: 0, Write: 0, Edit: 0, MultiEdit: 0, Bash: 0, Grep: 0,
        total: 0, toolCalls: []
      },
      fileChanges: { modified: 0, created: 0, deleted: 0 },
      fixValidated: false,
      duration: (Date.now() - startTime) / 1000,
      messages: 0
    };
  }
}

// Main test runner
async function main() {
  if (!process.env.ANTHROPIC_API_KEY) {
    console.error('❌ Error: ANTHROPIC_API_KEY environment variable not set');
    process.exit(1);
  }
  
  console.log('🚀 Claude Code TypeScript SDK Integration Test');
  console.log('==============================================');
  
  const vulnerabilityType = process.argv[2] || 'sql-injection';
  const validTypes = ['sql-injection', 'xss'];
  
  if (!validTypes.includes(vulnerabilityType)) {
    console.error(`❌ Invalid vulnerability type: ${vulnerabilityType}`);
    console.error(`Valid types: ${validTypes.join(', ')}`);
    process.exit(1);
  }
  
  const result = await runTest(vulnerabilityType);
  
  // Save results
  await fs.writeFile(
    'claude-sdk-test-results.json',
    JSON.stringify(result, null, 2)
  );
  
  process.exit(result.success ? 0 : 1);
}

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}