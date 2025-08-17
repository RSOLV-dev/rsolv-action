#!/usr/bin/env bun

/**
 * Test script to understand XSS validation issues
 * This will help us see what tests are being generated and why they fail
 */

import { TestGeneratingSecurityAnalyzer } from './src/ai/test-generator.js';
import { GitBasedTestValidator } from './src/ai/git-based-test-validator.js';
import { logger } from './src/utils/logger.js';
import type { GitHubIssue } from './src/types/index.js';

// Mock XSS issue data
const mockXSSIssue: GitHubIssue = {
  id: 'issue-289',
  number: 289,
  title: 'Cross-Site Scripting (XSS) vulnerability in app/views/tutorial.pug',
  body: `## 🚨 Security Vulnerability Detected

**Type**: Cross-Site Scripting (XSS)
**Severity**: High
**File**: app/views/tutorial.pug
**Line**: 22

### Description
A Cross-Site Scripting (XSS) vulnerability has been detected in the tutorial view. The vulnerability exists on line 22 where user input is rendered without proper escaping.

### Vulnerable Code
\`\`\`pug
// Line 22 in app/views/tutorial.pug
div.kg-card-markdown
  p!= tutorial.content
\`\`\`

The \`!=\` operator in Pug renders unescaped HTML, which allows malicious scripts to execute.

### Recommended Fix
Replace the unescaped output (\`!=\`) with escaped output (\`=\`):
\`\`\`pug
div.kg-card-markdown
  p= tutorial.content
\`\`\``,
  state: 'open',
  labels: ['security', 'rsolv:validated', 'severity:high'],
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString()
};

async function testXSSValidation() {
  try {
    console.log('🧪 Testing XSS vulnerability validation...\n');
    
    // Step 1: Generate tests for the XSS vulnerability
    console.log('1️⃣ Generating tests for XSS vulnerability...');
    
    const aiConfig = {
      provider: 'anthropic' as const,
      apiKey: process.env.ANTHROPIC_API_KEY || 'test-key',
      model: 'claude-3-5-sonnet-20241022',
      temperature: 0.2,
      maxTokens: 4000,
      useVendedCredentials: false
    };
    
    const testAnalyzer = new TestGeneratingSecurityAnalyzer(aiConfig);
    
    // Create a mock codebase with the vulnerable file
    const codebaseFiles = new Map<string, string>();
    codebaseFiles.set('app/views/tutorial.pug', `extends layout

block content
  .container
    h1= title
    
    .tutorial-content
      div.kg-card-markdown
        p!= tutorial.content
        
    .tutorial-meta
      p Posted by: #{tutorial.author}
      p Date: #{tutorial.date}
`);
    
    const mockConfig = {
      repository: {
        owner: 'RSOLV-dev',
        name: 'nodegoat-vulnerability-demo'
      },
      testGeneration: {
        enabled: true,
        validateFixes: true
      },
      fixValidation: {
        enabled: true,
        maxIterations: 3
      },
      enableSecurityAnalysis: true
    } as any;
    
    const testResults = await testAnalyzer.analyzeWithTestGeneration(
      mockXSSIssue,
      mockConfig,
      codebaseFiles
    );
    
    if (!testResults.generatedTests?.success) {
      console.error('❌ Failed to generate tests');
      return;
    }
    
    console.log('✅ Tests generated successfully');
    console.log(`   Framework: ${testResults.generatedTests.tests[0]?.framework}`);
    console.log(`   Test count: ${testResults.generatedTests.tests.length}`);
    
    // Step 2: Display the generated test code
    console.log('\n2️⃣ Generated test code:');
    console.log('─'.repeat(60));
    
    const testSuite = testResults.generatedTests.testSuite;
    if (testSuite) {
      console.log('RED Test (detect vulnerability):');
      console.log(testSuite.tests.red?.code || 'No RED test generated');
      console.log('\nGREEN Test (verify fix):');
      console.log(testSuite.tests.green?.code || 'No GREEN test generated');
      console.log('\nREFACTOR Test (maintain functionality):');
      console.log(testSuite.tests.refactor?.code || 'No REFACTOR test generated');
    }
    
    // Step 3: Simulate what a fix would look like
    console.log('\n3️⃣ Expected fix:');
    console.log('─'.repeat(60));
    console.log('Change line 22 from:');
    console.log('  p!= tutorial.content');
    console.log('To:');
    console.log('  p= tutorial.content');
    console.log('\nThis changes from unescaped (!=) to escaped (=) output in Pug.');
    
    // Step 4: Explain what the tests should validate
    console.log('\n4️⃣ What the tests should validate:');
    console.log('─'.repeat(60));
    console.log('RED Test: Should FAIL on vulnerable code (XSS executes)');
    console.log('         Should PASS on fixed code (XSS prevented)');
    console.log('\nGREEN Test: Should FAIL before fix is applied');
    console.log('           Should PASS after fix is applied');
    console.log('\nREFACTOR Test: Should PASS both before and after fix');
    console.log('              (legitimate content still displays)');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  }
}

// Run the test
testXSSValidation().catch(console.error);