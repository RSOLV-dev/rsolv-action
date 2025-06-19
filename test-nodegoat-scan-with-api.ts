#!/usr/bin/env bun
/**
 * Test RSOLV scanning on NodeGoat repository with full API patterns
 */

import { ScanOrchestrator } from './src/scanner/index.js';
import { logger } from './src/utils/logger.js';
import * as fs from 'fs';
import * as path from 'path';

const NODEGOAT_PATH = '../scripts/nodegoat-test';

async function scanNodeGoat() {
  // Set the API key from environment or command line
  const apiKey = process.env.RSOLV_API_KEY || process.argv[2];
  
  if (!apiKey) {
    logger.error('❌ No API key provided!');
    logger.info('Usage: RSOLV_API_KEY=your-key bun run test-nodegoat-scan-with-api.ts');
    logger.info('   or: bun run test-nodegoat-scan-with-api.ts your-api-key');
    process.exit(1);
  }
  
  // Set the API key in environment for pattern source
  process.env.RSOLV_API_KEY = apiKey;
  
  logger.info('🎯 RSOLV Security Scanner - NodeGoat Demo (Full API Patterns)');
  logger.info('============================================================');
  logger.info(`Scanning: ${NODEGOAT_PATH}`);
  logger.info(`Using API key: ${apiKey.substring(0, 10)}...`);
  
  // Check if NodeGoat exists
  if (!fs.existsSync(NODEGOAT_PATH)) {
    logger.error('NodeGoat not found at expected path');
    logger.info('Please ensure NodeGoat is cloned to scripts/nodegoat-test/');
    process.exit(1);
  }
  
  // Known vulnerable files in NodeGoat
  const vulnerableFiles = [
    'app/routes/allocations.js',
    'app/routes/profile.js', 
    'app/routes/contributions.js',
    'app/routes/memos.js',
    'app/routes/benefits.js',
    'app/routes/session.js',
    'app/routes/research.js',
    'app/data/user-dao.js',
    'app/data/allocations-dao.js',
    'app/data/benefits-dao.js',
    'app/data/memos-dao.js',
    'app/data/profile-dao.js',
    'server.js'
  ];
  
  logger.info(`\nScanning ${vulnerableFiles.length} files for vulnerabilities...`);
  
  const { SecurityDetectorV2 } = await import('./src/security/detector-v2.js');
  const { createPatternSource } = await import('./src/security/pattern-source.js');
  const detector = new SecurityDetectorV2(createPatternSource());
  
  let totalVulnerabilities = 0;
  const allVulnerabilities: any[] = [];
  
  for (const file of vulnerableFiles) {
    const filePath = path.join(NODEGOAT_PATH, file);
    
    if (!fs.existsSync(filePath)) {
      logger.warn(`File not found: ${file}`);
      continue;
    }
    
    const content = fs.readFileSync(filePath, 'utf-8');
    const language = file.endsWith('.js') ? 'javascript' : 'unknown';
    
    if (language === 'unknown') continue;
    
    logger.info(`\n📄 Scanning ${file}...`);
    
    try {
      const vulnerabilities = await detector.detect(content, language);
      
      if (vulnerabilities.length > 0) {
        totalVulnerabilities += vulnerabilities.length;
        logger.warn(`   ⚠️  Found ${vulnerabilities.length} vulnerabilities`);
        
        // Add file path to vulnerabilities
        vulnerabilities.forEach(v => {
          v.filePath = file;
          allVulnerabilities.push(v);
        });
        
        // Show first few vulnerabilities with more detail
        const sample = vulnerabilities.slice(0, 3);
        for (const vuln of sample) {
          logger.info(`      - Line ${vuln.line}: ${vuln.type}`);
          logger.info(`        ${vuln.description}`);
          if (vuln.snippet) {
            logger.info(`        Code: ${vuln.snippet.trim()}`);
          }
        }
        
        if (vulnerabilities.length > 3) {
          logger.info(`      ... and ${vulnerabilities.length - 3} more`);
        }
      } else {
        logger.info(`   ✅ No vulnerabilities detected`);
      }
    } catch (error) {
      logger.error(`   ❌ Error scanning file: ${error}`);
    }
  }
  
  // Group vulnerabilities by type
  const byType = allVulnerabilities.reduce((acc, vuln) => {
    if (!acc[vuln.type]) {
      acc[vuln.type] = { count: 0, files: new Set(), severities: {} };
    }
    acc[vuln.type].count++;
    acc[vuln.type].files.add(vuln.filePath);
    
    // Count severities
    const severity = vuln.severity || 'medium';
    acc[vuln.type].severities[severity] = (acc[vuln.type].severities[severity] || 0) + 1;
    
    return acc;
  }, {} as Record<string, { count: number; files: Set<string>; severities: Record<string, number> }>);
  
  logger.info('\n\n📊 SCAN SUMMARY');
  logger.info('═'.repeat(60));
  logger.info(`Total vulnerabilities found: ${totalVulnerabilities}`);
  logger.info(`Files with vulnerabilities: ${new Set(allVulnerabilities.map(v => v.filePath)).size}`);
  logger.info('\nVulnerabilities by type:');
  
  // Sort by count
  const sortedTypes = Object.entries(byType).sort((a, b) => b[1].count - a[1].count);
  
  for (const [type, data] of sortedTypes) {
    const severityStr = Object.entries(data.severities)
      .map(([sev, count]) => `${count} ${sev}`)
      .join(', ');
    logger.info(`  • ${type}: ${data.count} instances in ${data.files.size} files (${severityStr})`);
  }
  
  // Show some example vulnerabilities
  logger.info('\n📋 Example Issues That Would Be Created:');
  
  const exampleTypes = sortedTypes.slice(0, 3);
  for (const [type, _] of exampleTypes) {
    const examples = allVulnerabilities.filter(v => v.type === type).slice(0, 1);
    for (const vuln of examples) {
      logger.info(`\n  Issue: "${type.replace(/-/g, ' ').toUpperCase()} vulnerability in ${vuln.filePath}"`);
      logger.info(`  Description: ${vuln.description}`);
      logger.info(`  Severity: ${vuln.severity}`);
      logger.info(`  Line: ${vuln.line}`);
    }
  }
  
  logger.info('\n💡 What RSOLV Would Do Next:');
  logger.info('  1. Create GitHub issues for each vulnerability type');
  logger.info('  2. Group similar vulnerabilities in the same issue');
  logger.info('  3. Add the "rsolv:automate" label');
  logger.info('  4. Process issues to generate fix PRs');
  logger.info('  5. Each PR would fix all instances of that vulnerability type');
  
  logger.info('\n🚀 This is the complete "find and fix" workflow in action!');
  
  // Save results to file
  const resultsPath = 'nodegoat-scan-results.json';
  fs.writeFileSync(resultsPath, JSON.stringify({
    scanDate: new Date().toISOString(),
    totalVulnerabilities,
    filesScanned: vulnerableFiles.length,
    vulnerabilitiesByType: Object.fromEntries(
      Object.entries(byType).map(([type, data]) => [
        type,
        {
          count: data.count,
          files: Array.from(data.files),
          severities: data.severities
        }
      ])
    ),
    allVulnerabilities: allVulnerabilities.map(v => ({
      type: v.type,
      severity: v.severity,
      file: v.filePath,
      line: v.line,
      description: v.description
    }))
  }, null, 2));
  
  logger.info(`\n📁 Full results saved to: ${resultsPath}`);
}

// Run the scan
scanNodeGoat().catch(error => {
  logger.error('Scan failed:', error);
  process.exit(1);
});