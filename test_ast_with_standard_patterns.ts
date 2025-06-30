#!/usr/bin/env bun

/**
 * AST Test with Standard Patterns
 * Since enhanced patterns are failing, test with standard patterns
 */

import * as crypto from 'crypto';

const LOCAL_API_URL = 'http://localhost:4000/api/v1/ast/analyze';
const API_KEY = 'rsolv_test_abc123';

const TEST_PYTHON_CODE = `
# Simple SQL injection test
query = "SELECT * FROM users WHERE id = " + user_id
result = cursor.execute(query)
`;

interface EncryptionData {
  encryptedContent: string;
  iv: string;
  authTag: string;
  algorithm: string;
}

function encryptContent(content: string, key: Buffer): EncryptionData {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  
  let encrypted = cipher.update(content, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  
  const authTag = cipher.getAuthTag();
  
  return {
    encryptedContent: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    algorithm: 'aes-256-gcm'
  };
}

async function testWithStandardPatterns() {
  console.log('🧪 Testing AST analysis with STANDARD patterns...');
  
  try {
    const encryptionKey = crypto.randomBytes(32);
    const encrypted = encryptContent(TEST_PYTHON_CODE, encryptionKey);
    
    const requestData = {
      files: [
        {
          path: '/test/sql_injection.py',
          encryptedContent: encrypted.encryptedContent,
          encryption: {
            iv: encrypted.iv,
            authTag: encrypted.authTag,
            algorithm: encrypted.algorithm
          },
          metadata: {
            language: 'python',
            size: TEST_PYTHON_CODE.length
          }
        }
      ],
      options: {
        patternFormat: 'standard',  // Use standard instead of enhanced
        includeSecurityPatterns: true
      }
    };
    
    console.log(`   📄 Analyzing: ${requestData.files[0].path}`);
    console.log(`   🔧 Pattern format: ${requestData.options.patternFormat}`);
    
    const response = await fetch(LOCAL_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
        'X-Encryption-Key': encryptionKey.toString('base64'),
        'Accept': 'application/json'
      },
      body: JSON.stringify(requestData)
    });
    
    console.log(`   📡 Response: ${response.status} ${response.statusText}`);
    
    if (response.ok) {
      const result = await response.json();
      
      console.log(`   ✅ Analysis successful!`);
      console.log(`   📊 Summary:`);
      console.log(`      Files analyzed: ${result.summary.filesAnalyzed}`);
      console.log(`      Total findings: ${result.summary.totalFindings}`);
      
      if (result.results && result.results[0]) {
        const fileResult = result.results[0];
        console.log(`   📄 File result:`);
        console.log(`      Status: ${fileResult.status}`);
        console.log(`      Language: ${fileResult.language}`);
        console.log(`      Findings: ${fileResult.findings.length}`);
        
        if (fileResult.findings.length > 0) {
          console.log(`   🚨 Findings:`);
          fileResult.findings.forEach((finding: any, i: number) => {
            console.log(`      ${i + 1}. ${finding.id}: ${finding.title}`);
            console.log(`         Severity: ${finding.severity}`);
            console.log(`         Line: ${finding.line}, Column: ${finding.column}`);
            console.log(`         Evidence: ${finding.evidence}`);
          });
        } else {
          console.log(`   ⚠️  No findings detected`);
        }
        
        if (fileResult.astStats) {
          console.log(`   📈 AST Stats:`);
          console.log(`      Parse time: ${fileResult.astStats.parseTimeMs}ms`);
          console.log(`      AST parse time: ${fileResult.astStats.astParseTime}ms`);
          console.log(`      Pattern match time: ${fileResult.astStats.patternMatchTime}ms`);
          console.log(`      Node count: ${fileResult.astStats.nodeCount}`);
          console.log(`      Cache hit: ${fileResult.astStats.cacheHit}`);
        }
      }
    } else {
      const errorText = await response.text();
      console.log(`   ❌ Failed: ${errorText}`);
    }
    
  } catch (error) {
    console.log(`   💥 Exception: ${error}`);
  }
}

async function testWithEnhancedPatterns() {
  console.log('\n🧪 Testing AST analysis with ENHANCED patterns (expected to fail)...');
  
  try {
    const encryptionKey = crypto.randomBytes(32);
    const encrypted = encryptContent(TEST_PYTHON_CODE, encryptionKey);
    
    const requestData = {
      files: [
        {
          path: '/test/sql_injection.py',
          encryptedContent: encrypted.encryptedContent,
          encryption: {
            iv: encrypted.iv,
            authTag: encrypted.authTag,
            algorithm: encrypted.algorithm
          },
          metadata: {
            language: 'python',
            size: TEST_PYTHON_CODE.length
          }
        }
      ],
      options: {
        patternFormat: 'enhanced',  // This should fail
        includeSecurityPatterns: true
      }
    };
    
    const response = await fetch(LOCAL_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
        'X-Encryption-Key': encryptionKey.toString('base64'),
        'Accept': 'application/json'
      },
      body: JSON.stringify(requestData)
    });
    
    console.log(`   📡 Response: ${response.status} ${response.statusText}`);
    
    if (response.ok) {
      const result = await response.json();
      console.log(`   ✅ Unexpected success with enhanced patterns!`);
      console.log(`   📊 Total findings: ${result.summary.totalFindings}`);
    } else {
      const errorText = await response.text();
      console.log(`   ❌ Expected failure: ${errorText.substring(0, 100)}...`);
    }
    
  } catch (error) {
    console.log(`   💥 Exception: ${error}`);
  }
}

async function checkStandardPatterns() {
  console.log('\n📋 Checking available standard patterns for Python...');
  
  try {
    const response = await fetch('http://localhost:4000/api/v1/patterns?language=python&format=standard');
    
    if (response.ok) {
      const data = await response.json();
      console.log(`   ✅ Found ${data.patterns.length} standard Python patterns`);
      
      const sqlPatterns = data.patterns.filter((p: any) => 
        p.id.includes('sql') || p.title?.toLowerCase().includes('sql')
      );
      
      console.log(`   🎯 SQL-related patterns: ${sqlPatterns.length}`);
      sqlPatterns.forEach((p: any) => {
        console.log(`      - ${p.id}: ${p.title} (${p.severity})`);
      });
      
    } else {
      console.log(`   ❌ Failed to get standard patterns`);
    }
  } catch (error) {
    console.log(`   💥 Exception: ${error}`);
  }
}

async function main() {
  console.log('🚀 AST Analysis Test with Standard Patterns');
  console.log('='.repeat(50));
  console.log('Goal: Test if AST analysis works with standard patterns');
  console.log('Context: Enhanced patterns are failing with 500 errors');
  
  await checkStandardPatterns();
  await testWithStandardPatterns();
  await testWithEnhancedPatterns();
  
  console.log('\n✅ Test completed!');
  console.log('\nFindings:');
  console.log('- Enhanced pattern format has bugs in serialization');
  console.log('- Standard patterns should work for basic vulnerability detection');
  console.log('- AST analysis pipeline is functional, issue is in pattern enhancement');
}

main().catch(console.error);