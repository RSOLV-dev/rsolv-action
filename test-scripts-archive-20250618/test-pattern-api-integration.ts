#!/usr/bin/env bun

/**
 * Test RSOLV-action integration with RSOLV-api pattern endpoints
 * Verifies that the test customer can access all pattern tiers
 */

import { PatternAPIClient } from './src/security/pattern-api-client';
import { SecurityDetectorV2 } from './src/security/detector-v2';

const TEST_API_KEY = 'rsolv_test_abc123';
const API_URL = process.env.RSOLV_API_URL || 'http://localhost:4001';

console.log('🔍 Testing RSOLV-action Pattern API Integration\n');

// Test vulnerable code covering all tier patterns
const vulnerableCode = `
// SQL Injection (protected tier)
const query = db.query("SELECT * FROM users WHERE id = " + userId);
const query2 = connection.execute(\`SELECT * FROM products WHERE name = '\${productName}'\`);

// XSS (public tier)
element.innerHTML = userInput;
document.write(data);

// Command Injection (protected tier)
const exec = require('child_process').exec;
exec('ls ' + userInput);
spawn('git', ['clone', userRepo], {shell: true});

// Path Traversal (protected tier)
const file = path.join('./uploads', req.params.filename);
fs.readFile("./data/" + userFile);

// Weak Crypto (public tier)
crypto.createHash('md5').update(password);
const hash = crypto.createHash('sha1');

// Hardcoded Secrets (public tier)
const password = "admin123";
const apiKey = "sk-1234567890abcdef";

// Eval (protected tier)
eval(userCode);

// XXE (protected tier)
const parser = new DOMParser();
const doc = parser.parseFromString(xmlString, 'text/xml');

// Open Redirect (public tier)
res.redirect(req.query.url);

// Unsafe Regex (public tier)
const pattern = new RegExp("(a+)+$");

// Prototype Pollution (protected tier)
obj[key] = value;

// Insecure Deserialization (protected tier)
const data = JSON.parse(userInput);
unserialize(userData);

// NoSQL Injection (protected tier - if available)
db.collection.find({username: req.body.username});

// LDAP Injection (protected tier - if available)
ldap.search(\`(uid=\${username})\`);

// XPath Injection (protected tier - if available)
xpath.evaluate(\`//user[name='\${name}']\`);

// SSRF (protected tier - if available)
fetch(userProvidedUrl);
axios.get(req.query.url);
`;

async function testPatternAccess() {
  console.log('1️⃣ Testing with authenticated PatternAPIClient...');
  
  const client = new PatternAPIClient({
    apiUrl: API_URL,
    apiKey: TEST_API_KEY
  });

  try {
    // Fetch patterns for JavaScript
    const patterns = await client.fetchPatterns('javascript');
    console.log(`✅ Retrieved ${patterns.length} patterns via PatternAPIClient`);
    
    // Group patterns by type for analysis
    const patternsByType = patterns.reduce((acc, p) => {
      const type = p.type || 'UNKNOWN';
      acc[type] = (acc[type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    
    console.log('\n📊 Pattern distribution by type:');
    Object.entries(patternsByType).forEach(([type, count]) => {
      console.log(`   ${type}: ${count}`);
    });
    
    // Test pattern detection
    console.log('\n2️⃣ Testing pattern detection on vulnerable code...');
    const detector = new SecurityDetectorV2();
    const findings = await detector.detect(
      vulnerableCode,
      'javascript'
    );
    
    console.log(`\n✅ Detected ${findings.length} vulnerabilities:\n`);
    
    // Group findings by severity
    const findingsBySeverity = findings.reduce((acc, f) => {
      const severity = f.pattern.severity || 'unknown';
      if (!acc[severity]) acc[severity] = [];
      acc[severity].push(f);
      return acc;
    }, {} as Record<string, any[]>);
    
    // Display findings by severity
    ['critical', 'high', 'medium', 'low'].forEach(severity => {
      const severityFindings = findingsBySeverity[severity] || [];
      if (severityFindings.length > 0) {
        console.log(`${severity.toUpperCase()} (${severityFindings.length}):`);
        severityFindings.forEach(f => {
          console.log(`  - ${f.pattern.id} at line ${f.lineNumber}: ${f.pattern.name}`);
        });
        console.log('');
      }
    });
    
    // Test tier-specific access
    console.log('3️⃣ Testing tier-specific access...');
    
    // Try to fetch different tiers
    const tiers = ['public', 'protected', 'ai', 'enterprise'] as const;
    for (const tier of tiers) {
      try {
        const tierPatterns = await client.fetchPatternsByTier(tier, 'javascript');
        console.log(`   ${tier}: ✅ ${tierPatterns.length} patterns`);
      } catch (error: any) {
        console.log(`   ${tier}: ❌ ${error.message}`);
      }
    }
    
    // Verify we're getting protected patterns
    const protectedPatterns = patterns.filter(p => 
      ['critical', 'high'].includes(p.severity) ||
      ['SQL_INJECTION', 'COMMAND_INJECTION', 'XXE', 'PATH_TRAVERSAL'].includes(p.type)
    );
    
    console.log(`\n📊 Analysis:`);
    console.log(`   Total patterns: ${patterns.length}`);
    console.log(`   Protected patterns found: ${protectedPatterns.length}`);
    console.log(`   Vulnerabilities detected: ${findings.length}`);
    
    if (patterns.length > 15 && protectedPatterns.length > 5) {
      console.log('\n✅ SUCCESS: Test customer has full access to all pattern tiers!');
    } else {
      console.log('\n⚠️  WARNING: Test customer may not have full tier access');
      console.log(`   Expected more patterns (got ${patterns.length})`);
    }
    
  } catch (error) {
    console.error('❌ Error:', error);
  }
}

// Run the test
testPatternAccess().catch(console.error);