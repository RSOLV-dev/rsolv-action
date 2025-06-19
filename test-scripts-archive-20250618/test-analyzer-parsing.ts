#!/usr/bin/env bun
/**
 * Test our analyzer parsing with a real Claude Code response
 */

import { IssueContext } from './src/types/index.js';

// Import our parsing function
const { analyzeIssue } = await import('./src/ai/analyzer.js');

// Real Claude Code response from our test
const realClaudeResponse = `Since this appears to be a hypothetical example, I'll provide a comprehensive analysis of the timing attack vulnerability and solution:

## 1. Vulnerability Description

A timing attack vulnerability occurs when password comparison uses standard string equality (\`===\` or \`==\`), which returns immediately upon finding the first character mismatch. Attackers can measure response times to determine how many characters they've guessed correctly, gradually building up the correct password.

## 2. Vulnerable Code Location

**File**: \`src/auth/login.js\`  
**Line**: 15  
**Current vulnerable code**:
\`\`\`javascript
if (password === storedPassword) {
  // Grant access
}
\`\`\`

## 3. Fix Implementation

Replace the vulnerable comparison with a constant-time comparison:

\`\`\`javascript
const crypto = require('crypto');

// Replace line 15 with:
if (crypto.timingSafeEqual(Buffer.from(password), Buffer.from(storedPassword))) {
  // Grant access
}
\`\`\`

For hashed passwords (recommended):
\`\`\`javascript
const bcrypt = require('bcrypt');

// During login verification:
if (await bcrypt.compare(password, hashedPassword)) {
  // Grant access
}
\`\`\`

## 4. Why This Prevents Timing Attacks

- **\`crypto.timingSafeEqual()\`**: Compares buffers in constant time, checking every byte regardless of mismatches
- **\`bcrypt.compare()\`**: Uses constant-time comparison internally and adds computational complexity
- Both methods ensure response time doesn't reveal password length or partial matches
- Attackers cannot determine correct character positions through timing analysis

The fix prevents information leakage through execution time, making brute-force attacks significantly harder.`;

// Mock AI client that returns the real Claude response
const mockAiClient = {
  complete: async () => realClaudeResponse
};

// Mock issue
const mockIssue: IssueContext = {
  id: '123',
  number: 15,
  title: 'Fix timing attack in login.js',
  body: 'The login.js file uses string comparison for passwords which is vulnerable to timing attacks.',
  labels: ['rsolv:automate'],
  author: 'test-user',
  assignees: [],
  url: 'https://github.com/test/repo/issues/15',
  repository: {
    name: 'test-repo',
    owner: 'test-owner',
    fullName: 'test-owner/test-repo',
    url: 'https://github.com/test-owner/test-repo',
    defaultBranch: 'main'
  },
  createdAt: new Date().toISOString()
};

async function testAnalyzerParsing() {
  console.log('🧪 Testing analyzer parsing with real Claude Code response\n');
  
  console.log('📝 Real Claude Code response (first 300 chars):');
  console.log(realClaudeResponse.substring(0, 300) + '...\n');
  
  const config = { aiProvider: { provider: 'anthropic' as const } };
  
  try {
    const result = await analyzeIssue(mockIssue, config, mockAiClient);
    
    console.log('📊 Parsing Results:');
    console.log('==================');
    console.log(`Issue Type: ${result.issueType}`);
    console.log(`Complexity: ${result.estimatedComplexity}`);
    console.log(`Files to Modify: [${result.filesToModify.join(', ')}]`);
    console.log(`Suggested Approach: ${result.suggestedApproach.substring(0, 100)}...`);
    console.log(`Can Be Fixed: ${result.canBeFixed}`);
    console.log(`Confidence Score: ${result.confidenceScore}`);
    
    if (result.canBeFixed) {
      console.log('\n✅ SUCCESS: Issue marked as fixable!');
      console.log(`✅ Found ${result.filesToModify.length} files to modify`);
      console.log(`✅ Approach length: ${result.suggestedApproach.length} chars`);
    } else {
      console.log('\n❌ FAILED: Issue marked as not fixable');
      console.log('❌ This suggests our parsing logic needs improvement');
    }
    
    // Test specific expectations
    console.log('\n🔍 Detailed Analysis:');
    console.log('====================');
    
    const hasLoginFile = result.filesToModify.some(f => f.includes('login.js'));
    console.log(`Contains src/auth/login.js: ${hasLoginFile ? '✅' : '❌'}`);
    
    const hasApproach = result.suggestedApproach.length > 50;
    console.log(`Has substantial approach (>50 chars): ${hasApproach ? '✅' : '❌'}`);
    
    const mentionsCrypto = result.suggestedApproach.toLowerCase().includes('crypto');
    console.log(`Mentions crypto solution: ${mentionsCrypto ? '✅' : '❌'}`);
    
  } catch (error) {
    console.error('💥 Error during analysis:', error);
  }
}

if (import.meta.main) {
  testAnalyzerParsing();
}