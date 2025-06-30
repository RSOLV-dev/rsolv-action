#!/usr/bin/env bun

/**
 * Local AST Service Debug Test Script
 * 
 * Tests the local AST service at http://localhost:4000/api/v1/ast/analyze
 * with a Python SQL injection example to debug pattern matching.
 * 
 * This script provides detailed debugging output about:
 * 1. AST structure produced by the Python parser
 * 2. Available patterns and their configuration  
 * 3. Pattern matching logic and results
 * 4. Full AST analysis response
 */

import * as crypto from 'crypto';

const LOCAL_API_URL = 'http://localhost:4001/api/v1/ast/analyze';
const API_KEY = 'rsolv_test_abc123'; // Test API key with enterprise/AI access

// Test Python code with SQL injection vulnerability
const VULNERABLE_PYTHON_CODE = `
# Python SQL injection vulnerability test case
import sqlite3

def get_user_data(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string concatenation in SQL query
    query = "SELECT * FROM users WHERE id = " + user_id
    
    cursor.execute(query)
    result = cursor.fetchone()
    
    conn.close()
    return result

def safe_get_user_data(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # SAFE: Using parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    
    cursor.execute(query, (user_id,))
    result = cursor.fetchone()
    
    conn.close()
    return result
`;

interface EncryptionData {
  encryptedContent: string;
  iv: string;
  authTag: string;
  algorithm: string;
}

interface FileData {
  path: string;
  encryptedContent: string;
  encryption: {
    iv: string;
    authTag: string;
    algorithm: string;
  };
  metadata: {
    language: string;
    size: number;
  };
}

interface ASTAnalysisRequest {
  files: FileData[];
  options: {
    patternFormat: string;
    includeSecurityPatterns: boolean;
  };
  sessionId?: string;
}

interface ASTAnalysisResponse {
  requestId: string;
  session: {
    sessionId: string;
    expiresAt: string;
  };
  results: Array<{
    path: string;
    status: string;
    language: string;
    findings: Array<{
      id: string;
      severity: string;
      title: string;
      description: string;
      line: number;
      column: number;
      evidence: string;
      confidence: number;
    }>;
    astStats: {
      parseTimeMs: number;
      astParseTime: number;
      patternMatchTime: number;
      cacheHit: boolean;
      nodeCount: number;
    };
    error?: {
      type: string;
      message: string;
    };
  }>;
  summary: {
    filesAnalyzed: number;
    filesWithFindings: number;
    totalFindings: number;
    findingsBySeverity: Record<string, number>;
    findingsByLanguage: Record<string, number>;
  };
  timing: {
    totalMs: number;
    breakdown: {
      decryption: number;
      parsing: number;
      patternMatching: number;
      analysis: number;
      overhead: number;
    };
  };
}

/**
 * Encrypt content using AES-256-GCM
 */
function encryptContent(content: string, key: Buffer): EncryptionData {
  const iv = crypto.randomBytes(12); // 96-bit IV for GCM
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

/**
 * Test the health endpoint first
 */
async function testHealthEndpoint(): Promise<boolean> {
  try {
    console.log('🏥 Testing health endpoint...');
    const response = await fetch('http://localhost:4001/health');
    
    if (response.ok) {
      console.log('   ✅ Server is healthy and responding');
      return true;
    } else {
      console.log(`   ❌ Health check failed: ${response.status} ${response.statusText}`);
      return false;
    }
  } catch (error) {
    console.log(`   ❌ Health check failed: ${error}`);
    return false;
  }
}

/**
 * Test pattern availability
 */
async function testPatternAvailability(): Promise<void> {
  try {
    console.log('\n🔍 Testing pattern availability...');
    const response = await fetch('http://localhost:4001/api/v1/patterns?language=python&format=enhanced', {
      headers: {
        'Accept': 'application/json'
      }
    });
    
    if (response.ok) {
      const data = await response.json();
      console.log(`   ✅ Found ${data.patterns?.length || 0} Python patterns`);
      
      // Look for SQL injection patterns specifically
      const sqlPatterns = data.patterns?.filter((p: any) => 
        p.id.includes('sql') || p.title?.toLowerCase().includes('sql')
      ) || [];
      
      console.log(`   📊 SQL-related patterns: ${sqlPatterns.length}`);
      
      for (const pattern of sqlPatterns.slice(0, 3)) {
        console.log(`      - ${pattern.id}: ${pattern.title}`);
        console.log(`        Severity: ${pattern.severity}, Confidence: ${pattern.min_confidence || 'N/A'}`);
        
        if (pattern.ast_rules) {
          console.log(`        AST Rules: ${Object.keys(pattern.ast_rules).join(', ')}`);
        }
        if (pattern.context_rules) {
          console.log(`        Context Rules: ${Object.keys(pattern.context_rules).join(', ')}`);
        }
      }
    } else {
      console.log(`   ❌ Pattern endpoint failed: ${response.status} ${response.statusText}`);
      const errorText = await response.text();
      console.log(`   Error details: ${errorText}`);
    }
  } catch (error) {
    console.log(`   ❌ Pattern availability test failed: ${error}`);
  }
}

/**
 * Main AST analysis test
 */
async function testASTAnalysis(): Promise<void> {
  try {
    console.log('\n🧪 Testing AST Analysis...');
    
    // Generate encryption key
    const encryptionKey = crypto.randomBytes(32); // 256-bit key for AES-256
    
    // Encrypt the Python code
    const encrypted = encryptContent(VULNERABLE_PYTHON_CODE, encryptionKey);
    
    // Prepare the request
    const requestData: ASTAnalysisRequest = {
      files: [
        {
          path: '/test/vulnerable_sql.py',
          encryptedContent: encrypted.encryptedContent,
          encryption: {
            iv: encrypted.iv,
            authTag: encrypted.authTag,
            algorithm: encrypted.algorithm
          },
          metadata: {
            language: 'python',
            size: VULNERABLE_PYTHON_CODE.length
          }
        }
      ],
      options: {
        patternFormat: 'enhanced',
        includeSecurityPatterns: true
      }
    };
    
    console.log(`   📄 Analyzing Python file: ${requestData.files[0].path}`);
    console.log(`   📦 File size: ${requestData.files[0].metadata.size} bytes`);
    console.log(`   🔐 Encryption key: ${encryptionKey.toString('base64').substring(0, 16)}...`);
    
    // Make the request
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
    
    console.log(`   📡 Response status: ${response.status} ${response.statusText}`);
    
    if (!response.ok) {
      const errorText = await response.text();
      console.log(`   ❌ Request failed:`);
      console.log(`   ${errorText}`);
      return;
    }
    
    // Parse the response
    const result: ASTAnalysisResponse = await response.json();
    
    console.log(`   ✅ Analysis completed successfully!`);
    console.log(`   🆔 Request ID: ${result.requestId}`);
    console.log(`   🔗 Session ID: ${result.session.sessionId}`);
    
    // Analyze results in detail
    analyzeResults(result);
    
  } catch (error) {
    console.log(`   ❌ AST analysis test failed: ${error}`);
  }
}

/**
 * Analyze the AST results in detail
 */
function analyzeResults(result: ASTAnalysisResponse): void {
  console.log('\n📊 DETAILED ANALYSIS RESULTS');
  console.log('='.repeat(50));
  
  // Summary
  console.log(`\n📈 Summary:`);
  console.log(`   Files analyzed: ${result.summary.filesAnalyzed}`);
  console.log(`   Files with findings: ${result.summary.filesWithFindings}`);
  console.log(`   Total findings: ${result.summary.totalFindings}`);
  
  if (result.summary.findingsBySeverity) {
    console.log(`   Findings by severity:`);
    for (const [severity, count] of Object.entries(result.summary.findingsBySeverity)) {
      if (count > 0) {
        console.log(`     - ${severity}: ${count}`);
      }
    }
  }
  
  // Timing analysis
  console.log(`\n⏱️  Performance:`);
  console.log(`   Total time: ${result.timing.totalMs}ms`);
  console.log(`   Breakdown:`);
  console.log(`     - Decryption: ${result.timing.breakdown.decryption}ms`);
  console.log(`     - Parsing: ${result.timing.breakdown.parsing}ms`);
  console.log(`     - Pattern matching: ${result.timing.breakdown.patternMatching}ms`);
  console.log(`     - Analysis: ${result.timing.breakdown.analysis}ms`);
  console.log(`     - Overhead: ${result.timing.breakdown.overhead}ms`);
  
  // File-level results
  for (const fileResult of result.results) {
    console.log(`\n📄 File: ${fileResult.path}`);
    console.log(`   Status: ${fileResult.status}`);
    console.log(`   Language: ${fileResult.language}`);
    console.log(`   Findings: ${fileResult.findings.length}`);
    
    // AST Stats
    if (fileResult.astStats) {
      console.log(`   AST Statistics:`);
      console.log(`     - Parse time: ${fileResult.astStats.parseTimeMs}ms`);
      console.log(`     - AST parse time: ${fileResult.astStats.astParseTime}ms`);
      console.log(`     - Pattern match time: ${fileResult.astStats.patternMatchTime}ms`);
      console.log(`     - Cache hit: ${fileResult.astStats.cacheHit}`);
      console.log(`     - Node count: ${fileResult.astStats.nodeCount}`);
    }
    
    // Individual findings
    if (fileResult.findings.length > 0) {
      console.log(`\n   🚨 Security Findings:`);
      for (const [index, finding] of fileResult.findings.entries()) {
        console.log(`\n   Finding #${index + 1}:`);
        console.log(`     ID: ${finding.id}`);
        console.log(`     Title: ${finding.title}`);
        console.log(`     Severity: ${finding.severity.toUpperCase()}`);
        console.log(`     Confidence: ${finding.confidence}`);
        console.log(`     Location: Line ${finding.line}, Column ${finding.column}`);
        console.log(`     Description: ${finding.description}`);
        console.log(`     Evidence: ${finding.evidence}`);
      }
    } else {
      console.log(`\n   ⚠️  NO FINDINGS DETECTED`);
      console.log(`   This could indicate:`);
      console.log(`     - Pattern matching is not working correctly`);
      console.log(`     - AST parsing failed`);
      console.log(`     - Patterns are not configured for this vulnerability`);
      console.log(`     - The vulnerability pattern doesn't match the AST structure`);
    }
    
    // Error details if any
    if (fileResult.status === 'error' && fileResult.error) {
      console.log(`\n   ❌ Error Details:`);
      console.log(`     Type: ${fileResult.error.type}`);
      console.log(`     Message: ${fileResult.error.message}`);
    }
  }
}

/**
 * Additional debug tests
 */
async function runAdditionalDebugTests(): Promise<void> {
  console.log('\n🔧 ADDITIONAL DEBUG TESTS');
  console.log('='.repeat(50));
  
  // Test with minimal vulnerable code
  const minimalVulnCode = 'query = "SELECT * FROM users WHERE id = " + user_id';
  await testSpecificCode('Minimal SQL Injection', minimalVulnCode, '/test/minimal.py');
  
  // Test with safe code
  const safeCode = 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))';
  await testSpecificCode('Safe Parameterized Query', safeCode, '/test/safe.py');
}

async function testSpecificCode(testName: string, code: string, path: string): Promise<void> {
  try {
    console.log(`\n🧪 ${testName}:`);
    console.log(`   Code: ${code}`);
    
    const encryptionKey = crypto.randomBytes(32);
    const encrypted = encryptContent(code, encryptionKey);
    
    const requestData: ASTAnalysisRequest = {
      files: [
        {
          path: path,
          encryptedContent: encrypted.encryptedContent,
          encryption: {
            iv: encrypted.iv,
            authTag: encrypted.authTag,
            algorithm: encrypted.algorithm
          },
          metadata: {
            language: 'python',
            size: code.length
          }
        }
      ],
      options: {
        patternFormat: 'enhanced',
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
    
    if (response.ok) {
      const result: ASTAnalysisResponse = await response.json();
      const findings = result.results[0]?.findings || [];
      console.log(`   Result: ${findings.length} findings`);
      
      if (findings.length > 0) {
        for (const finding of findings) {
          console.log(`     - ${finding.id}: ${finding.title} (${finding.severity})`);
        }
      }
    } else {
      console.log(`   ❌ Failed: ${response.status} ${response.statusText}`);
    }
    
  } catch (error) {
    console.log(`   ❌ Error: ${error}`);
  }
}

/**
 * Main execution
 */
async function main(): Promise<void> {
  console.log('🚀 RSOLV Local AST Service Debug Test');
  console.log('='.repeat(50));
  console.log(`Target: ${LOCAL_API_URL}`);
  console.log(`API Key: ${API_KEY}`);
  console.log(`Test Code: Python SQL injection vulnerability`);
  
  // Step 1: Health check
  const isHealthy = await testHealthEndpoint();
  if (!isHealthy) {
    console.log('\n❌ Server is not healthy. Please start the server with: mix phx.server');
    process.exit(1);
  }
  
  // Step 2: Check pattern availability
  await testPatternAvailability();
  
  // Step 3: Main AST analysis test
  await testASTAnalysis();
  
  // Step 4: Additional debug tests
  await runAdditionalDebugTests();
  
  console.log('\n✅ Debug test completed!');
  console.log('\nTo further debug:');
  console.log('1. Check the server logs for detailed AST parsing output');
  console.log('2. Verify Python parser is working: priv/parsers/python/parser.py');
  console.log('3. Check pattern configuration in the enhanced patterns API');
  console.log('4. Review AST structure in the analysis service logs');
}

// Run the test
main().catch(console.error);