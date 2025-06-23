#!/usr/bin/env node

/**
 * Local test script for Claude Code SDK integration
 * Tests in-place editing capabilities and tool usage patterns
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const exec = promisify(require('child_process').exec);

// Test configuration
const TEST_DIR = path.join(process.cwd(), 'test-claude-code-repo');
const VULNERABILITIES = {
  'sql-injection': {
    file: 'app.js',
    content: `const express = require('express');
const mysql = require('mysql2');

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  // VULNERABLE: SQL injection through string concatenation
  const query = "SELECT * FROM users WHERE id = " + userId;
  db.query(query, (err, results) => {
    if (err) {
      res.status(500).send('Error');
    } else {
      res.json(results);
    }
  });
});`,
    expectedFix: ['?', 'parameterized', 'prepared']
  },
  'xss': {
    file: 'template.js',
    content: `function renderUserProfile(user) {
  // VULNERABLE: Direct HTML injection without escaping
  return \`
    <div class="user-profile">
      <h1>Welcome \${user.name}</h1>
      <p>Bio: \${user.bio}</p>
    </div>
  \`;
}`,
    expectedFix: ['escape', 'sanitize', 'encode', 'textContent']
  }
};

async function setupTestRepo(vulnerabilityType) {
  console.log(`\n📁 Setting up test repository for ${vulnerabilityType}...`);
  
  // Clean up if exists
  if (fs.existsSync(TEST_DIR)) {
    await exec(`rm -rf ${TEST_DIR}`);
  }
  
  // Create and initialize repo
  fs.mkdirSync(TEST_DIR, { recursive: true });
  process.chdir(TEST_DIR);
  
  await exec('git init');
  await exec('git config user.name "RSOLV Test"');
  await exec('git config user.email "test@rsolv.ai"');
  
  // Create vulnerable file
  const vuln = VULNERABILITIES[vulnerabilityType];
  fs.writeFileSync(vuln.file, vuln.content);
  
  await exec(`git add ${vuln.file}`);
  await exec('git commit -m "Add vulnerable code for testing"');
  
  console.log('✅ Test repository created');
  return vuln;
}

async function runClaudeCode(vulnerabilityType, vulnFile) {
  console.log('\n🤖 Running Claude Code with tool monitoring...');
  
  const toolUsage = {
    Read: 0,
    Write: 0,
    Edit: 0,
    MultiEdit: 0,
    Bash: 0,
    Grep: 0,
    totalCalls: 0,
    messages: []
  };
  
  return new Promise((resolve, reject) => {
    const prompt = `Fix the ${vulnerabilityType} vulnerability in ${vulnFile}. 
Make the minimal changes necessary to fix the security issue while preserving functionality.
Edit the existing file rather than creating a new one.`;
    
    const claude = spawn('npx', [
      '@anthropic-ai/claude-code',
      '--print',
      '--output-format', 'stream-json',
      '--max-turns', '5',
      '--allowedTools', 'Read,Write,Edit,MultiEdit,Bash,Grep',
      '--append-system-prompt', 'When fixing vulnerabilities, you MUST edit existing files using Edit or MultiEdit tools. Do not create new files. Make minimal, surgical changes to fix security issues.',
      prompt
    ], {
      cwd: TEST_DIR,
      env: { ...process.env, ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY }
    });
    
    let output = '';
    
    claude.stdout.on('data', (data) => {
      const text = data.toString();
      output += text;
      
      // Parse streaming JSON
      const lines = text.split('\n').filter(l => l.trim());
      for (const line of lines) {
        try {
          const msg = JSON.parse(line);
          
          // Track tool usage
          if (msg.type === 'message' && msg.role === 'assistant' && msg.content) {
            for (const block of msg.content) {
              if (block.type === 'tool_use') {
                toolUsage.totalCalls++;
                const toolName = block.name;
                if (toolUsage[toolName] !== undefined) {
                  toolUsage[toolName]++;
                }
                toolUsage.messages.push({
                  tool: toolName,
                  input: block.input
                });
              }
            }
          }
          
          // Show assistant messages
          if (msg.type === 'message' && msg.role === 'assistant') {
            for (const block of msg.content || []) {
              if (block.type === 'text') {
                console.log('Claude:', block.text.substring(0, 100) + '...');
              }
            }
          }
        } catch (e) {
          // Not JSON, skip
        }
      }
    });
    
    claude.stderr.on('data', (data) => {
      console.error('Claude stderr:', data.toString());
    });
    
    claude.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`Claude Code exited with code ${code}`));
      } else {
        resolve({ toolUsage, output });
      }
    });
  });
}

async function validateResults(vulnerabilityType, toolUsage) {
  console.log('\n📊 Analyzing results...');
  
  // Check tool usage patterns
  console.log('\n=== Tool Usage Report ===');
  console.log(`Total tool calls: ${toolUsage.totalCalls}`);
  console.log(`Read: ${toolUsage.Read}`);
  console.log(`Edit: ${toolUsage.Edit}`);
  console.log(`MultiEdit: ${toolUsage.MultiEdit}`);
  console.log(`Write: ${toolUsage.Write}`);
  console.log(`Bash: ${toolUsage.Bash}`);
  console.log(`Grep: ${toolUsage.Grep}`);
  
  const editRatio = (toolUsage.Edit + toolUsage.MultiEdit) / Math.max(1, toolUsage.totalCalls);
  console.log(`\nEdit tool usage ratio: ${(editRatio * 100).toFixed(1)}%`);
  
  // Check git changes
  const { stdout: gitStatus } = await exec('git status --porcelain');
  const { stdout: gitDiff } = await exec('git diff');
  
  console.log('\n=== Git Status ===');
  console.log(gitStatus || '(no changes)');
  
  // Count file changes
  const modifiedFiles = gitStatus.split('\n').filter(l => l.startsWith(' M')).length;
  const newFiles = gitStatus.split('\n').filter(l => l.startsWith('??')).length;
  
  console.log(`\nModified files: ${modifiedFiles}`);
  console.log(`New files: ${newFiles}`);
  
  // Check if vulnerability was fixed
  const vuln = VULNERABILITIES[vulnerabilityType];
  let fixDetected = false;
  for (const pattern of vuln.expectedFix) {
    if (gitDiff.includes(pattern)) {
      fixDetected = true;
      break;
    }
  }
  
  // Generate report
  const results = {
    vulnerabilityType,
    toolUsage: {
      total: toolUsage.totalCalls,
      editRatio: editRatio,
      breakdown: {
        Read: toolUsage.Read,
        Edit: toolUsage.Edit,
        MultiEdit: toolUsage.MultiEdit,
        Write: toolUsage.Write,
        Other: toolUsage.Bash + toolUsage.Grep
      }
    },
    fileChanges: {
      modified: modifiedFiles,
      new: newFiles
    },
    fixDetected,
    success: editRatio >= 0.5 && newFiles === 0 && fixDetected
  };
  
  // Print summary
  console.log('\n=== Test Summary ===');
  console.log(`✅ In-place editing: ${newFiles === 0 ? 'PASS' : 'FAIL'} (${newFiles} new files)`);
  console.log(`✅ Tool usage: ${editRatio >= 0.5 ? 'PASS' : 'FAIL'} (${(editRatio * 100).toFixed(1)}% Edit usage)`);
  console.log(`✅ Fix applied: ${fixDetected ? 'PASS' : 'FAIL'}`);
  console.log(`\nOverall: ${results.success ? '✅ PASS' : '❌ FAIL'}`);
  
  return results;
}

async function main() {
  if (!process.env.ANTHROPIC_API_KEY) {
    console.error('❌ Error: ANTHROPIC_API_KEY environment variable not set');
    process.exit(1);
  }
  
  console.log('🚀 Claude Code In-Place Editing Test Suite');
  console.log('==========================================');
  
  const vulnerabilityType = process.argv[2] || 'sql-injection';
  
  if (!VULNERABILITIES[vulnerabilityType]) {
    console.error(`❌ Unknown vulnerability type: ${vulnerabilityType}`);
    console.error(`Available types: ${Object.keys(VULNERABILITIES).join(', ')}`);
    process.exit(1);
  }
  
  try {
    // Setup test repository
    const vuln = await setupTestRepo(vulnerabilityType);
    
    // Run Claude Code
    const { toolUsage, output } = await runClaudeCode(vulnerabilityType, vuln.file);
    
    // Save output for debugging
    fs.writeFileSync('claude-output.json', output);
    
    // Validate results
    const results = await validateResults(vulnerabilityType, toolUsage);
    
    // Save results
    fs.writeFileSync('test-results.json', JSON.stringify(results, null, 2));
    
    if (!results.success) {
      process.exit(1);
    }
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
    process.exit(1);
  }
}

// Run if executed directly
if (require.main === module) {
  main().catch(console.error);
}

module.exports = { setupTestRepo, runClaudeCode, validateResults };