#!/usr/bin/env node

/**
 * Simple test of Claude Code SDK tool usage patterns
 */

const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

async function testClaudeCodeTools() {
  console.log('🧪 Testing Claude Code SDK tool usage...\n');
  
  // Check if API key is set
  if (!process.env.ANTHROPIC_API_KEY) {
    console.error('❌ Error: ANTHROPIC_API_KEY environment variable not set');
    console.error('Please set: export ANTHROPIC_API_KEY=your-api-key');
    process.exit(1);
  }
  
  // Create a simple test
  const testDir = path.join(process.cwd(), 'claude-code-test');
  
  // Cleanup
  if (fs.existsSync(testDir)) {
    fs.rmSync(testDir, { recursive: true, force: true });
  }
  
  fs.mkdirSync(testDir);
  
  // Create a simple vulnerable file
  const vulnerableCode = `function getUserData(userId) {
  // VULNERABLE: SQL injection
  const query = "SELECT * FROM users WHERE id = " + userId;
  return db.query(query);
}`;
  
  fs.writeFileSync(path.join(testDir, 'vulnerable.js'), vulnerableCode);
  
  console.log('📝 Created test file with SQL injection vulnerability\n');
  
  // Run Claude Code with specific prompting
  console.log('🤖 Running Claude Code...\n');
  
  const command = `cd ${testDir} && npx @anthropic-ai/claude-code --print --output-format json --max-turns 3 --allowedTools "Read,Edit,MultiEdit" "Fix the SQL injection vulnerability in vulnerable.js by using parameterized queries. Use the Edit tool to modify the existing file."`;
  
  exec(command, (error, stdout, stderr) => {
    if (error) {
      console.error('❌ Error running Claude Code:', error);
      return;
    }
    
    if (stderr) {
      console.error('Stderr:', stderr);
    }
    
    try {
      const result = JSON.parse(stdout);
      
      // Analyze tool usage
      let toolUsage = {
        Read: 0,
        Edit: 0,
        MultiEdit: 0,
        Write: 0,
        total: 0
      };
      
      // Count tool usage in messages
      if (result.messages) {
        for (const msg of result.messages) {
          if (msg.content && Array.isArray(msg.content)) {
            for (const block of msg.content) {
              if (block.type === 'tool_use') {
                toolUsage.total++;
                if (toolUsage[block.name] !== undefined) {
                  toolUsage[block.name]++;
                }
              }
            }
          }
        }
      }
      
      console.log('\n📊 Tool Usage Summary:');
      console.log('Total tool calls:', toolUsage.total);
      console.log('Read:', toolUsage.Read);
      console.log('Edit:', toolUsage.Edit);
      console.log('MultiEdit:', toolUsage.MultiEdit);
      console.log('Write:', toolUsage.Write);
      
      // Check the result
      const fixedFile = path.join(testDir, 'vulnerable.js');
      if (fs.existsSync(fixedFile)) {
        const fixedCode = fs.readFileSync(fixedFile, 'utf8');
        console.log('\n📄 Fixed code:');
        console.log(fixedCode);
        
        if (fixedCode.includes('?') || fixedCode.includes('parameterized')) {
          console.log('\n✅ SUCCESS: SQL injection fixed with parameterized query');
        } else {
          console.log('\n❌ FAILURE: SQL injection not properly fixed');
        }
      }
      
      // Cleanup
      fs.rmSync(testDir, { recursive: true, force: true });
      
    } catch (e) {
      console.error('Failed to parse JSON:', e);
      console.log('Raw output:', stdout);
    }
  });
}

// Run test
testClaudeCodeTools().catch(console.error);