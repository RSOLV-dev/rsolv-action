#!/usr/bin/env bun

/**
 * Test pattern detection with all tiers using test endpoint
 */

import { SecurityDetectorV2 } from './src/security/detector-v2';
import type { SecurityPattern } from './src/security/types';

const API_URL = process.env.RSOLV_API_URL || 'http://localhost:4001';

console.log('🔍 Testing Pattern Detection with All Tiers\n');

// Test code with various vulnerabilities
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
`;

async function testWithAllPatterns() {
  try {
    // Fetch all patterns from test endpoint
    console.log('📥 Fetching all patterns from test endpoint...');
    const response = await fetch(`${API_URL}/api/v1/test/patterns/javascript`);
    const data = await response.json();
    
    console.log(`✅ Retrieved ${data.total_count} patterns`);
    console.log(`   Tier distribution:`, data.tier_distribution);
    console.log('');
    
    // Convert API format to SecurityPattern format
    const patterns: SecurityPattern[] = data.patterns.map((p: any) => ({
      id: p.id,
      name: p.name,
      type: p.type,
      description: p.description,
      severity: p.severity,
      patterns: {
        regex: p.patterns.regex || p.patterns
      },
      languages: p.languages,
      frameworks: p.frameworks || [],
      recommendation: p.recommendation,
      cweId: p.cweId || p.cwe_id,
      owaspCategory: p.owaspCategory || p.owasp_category,
      testCases: p.testCases || p.test_cases || { vulnerable: [], safe: [] }
    }));
    
    // Run detection
    console.log('🔎 Running detection on test code...');
    const detector = new SecurityDetectorV2();
    const findings = await detector.detectVulnerabilities(
      vulnerableCode,
      'test.js',
      patterns
    );
    
    console.log(`\n✅ Detected ${findings.length} vulnerabilities:\n`);
    
    // Group findings by tier
    const findingsByTier: Record<string, any[]> = {};
    findings.forEach(f => {
      const tier = getPatternTier(f.pattern);
      if (!findingsByTier[tier]) findingsByTier[tier] = [];
      findingsByTier[tier].push(f);
    });
    
    // Display findings by tier
    Object.entries(findingsByTier).forEach(([tier, tierFindings]) => {
      console.log(`${tier.toUpperCase()} TIER (${tierFindings.length} findings):`);
      tierFindings.forEach(f => {
        console.log(`  - ${f.pattern.id} (line ${f.lineNumber}): ${f.pattern.name}`);
      });
      console.log('');
    });
    
    // Show coverage
    const expectedVulns = [
      'SQL Injection', 'XSS', 'Command Injection', 'Path Traversal',
      'Weak Crypto', 'Hardcoded Secrets', 'Eval', 'XXE', 
      'Open Redirect', 'Unsafe Regex', 'Prototype Pollution',
      'Insecure Deserialization'
    ];
    
    const detectedTypes = new Set(findings.map(f => f.pattern.type));
    console.log('📊 Detection Coverage:');
    console.log(`   Expected: ${expectedVulns.length} vulnerability types`);
    console.log(`   Detected: ${detectedTypes.size} unique types`);
    console.log(`   Coverage: ${Math.round(detectedTypes.size / expectedVulns.length * 100)}%`);
    
  } catch (error) {
    console.error('❌ Error:', error);
  }
}

function getPatternTier(pattern: SecurityPattern): string {
  // Approximate tier based on severity and pattern ID
  if (pattern.id.includes('hardcoded') || 
      pattern.id.includes('weak-crypto') ||
      pattern.id.includes('xss') ||
      pattern.id.includes('open-redirect') ||
      pattern.id.includes('unsafe-regex') ||
      pattern.id.includes('debug') ||
      pattern.id.includes('csrf') ||
      pattern.id.includes('insecure-random')) {
    return 'public';
  }
  return 'protected';
}

// Run the test
testWithAllPatterns();