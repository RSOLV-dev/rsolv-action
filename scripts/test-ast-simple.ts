#!/usr/bin/env node

const crypto = require('crypto');
const axios = require('axios');

// Simple vulnerable code
const vulnerableCode = `
const userId = req.params.id;
const query = "SELECT * FROM users WHERE id = " + userId;
db.query(query);
`;

async function testAST() {
  // Generate encryption key
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  
  // Encrypt the code
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(vulnerableCode, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const authTag = cipher.getAuthTag();
  
  // Prepare request
  const request = {
    requestId: `test-${Date.now()}`,
    files: [{
      path: 'vulnerable.js',
      encryptedContent: encrypted.toString('base64'),
      encryption: {
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64'),
        algorithm: 'aes-256-gcm'
      },
      metadata: {
        language: 'javascript',
        size: Buffer.byteLength(vulnerableCode),
        contentHash: crypto.createHash('sha256').update(vulnerableCode).digest('hex')
      }
    }],
    options: {
      patternFormat: 'enhanced',
      includeSecurityPatterns: true,
      debug: {
        includeRawAst: true,
        includeTiming: true
      }
    }
  };
  
  console.log('📤 Sending request to AST endpoint...');
  console.log('Code to analyze:', vulnerableCode);
  
  try {
    const response = await axios.post('http://localhost:4001/api/v1/ast/analyze', request, {
      headers: {
        'X-API-Key': 'rsolv_test_abc123',
        'X-Encryption-Key': key.toString('base64'),
        'Content-Type': 'application/json'
      }
    });
    
    console.log('\n📥 Response:');
    console.log(JSON.stringify(response.data, null, 2));
    
    // Check results
    const result = response.data.results[0];
    if (result) {
      console.log(`\n✅ File analyzed: ${result.path}`);
      console.log(`Status: ${result.status}`);
      console.log(`Language: ${result.language}`);
      console.log(`Findings: ${result.findings?.length || 0}`);
      
      if (result.findings?.length > 0) {
        console.log('\n🚨 Vulnerabilities found:');
        result.findings.forEach(f => {
          console.log(`- ${f.patternName} (${f.severity})`);
          console.log(`  Confidence: ${(f.confidence * 100).toFixed(0)}%`);
          console.log(`  Line: ${f.location.startLine}`);
        });
      }
      
      if (result.rawAst) {
        console.log('\n🌳 AST nodes:', Object.keys(result.rawAst));
      }
    }
    
  } catch (error) {
    console.error('❌ Error:', error.response?.data || error.message);
  }
}

testAST().catch(console.error);