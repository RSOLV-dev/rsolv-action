#!/usr/bin/env bun
/**
 * Test RSOLV scanning on NodeGoat repository
 */

import { ScanOrchestrator } from './src/scanner/index.js';
import { logger } from './src/utils/logger.js';
import * as fs from 'fs';
import * as path from 'path';

const NODEGOAT_PATH = '../scripts/nodegoat-test';

async function scanNodeGoat() {
  logger.info('🎯 RSOLV Security Scanner - NodeGoat Demo');
  logger.info('========================================');
  logger.info(`Scanning: ${NODEGOAT_PATH}`);
  
  // Check if NodeGoat exists
  if (!fs.existsSync(NODEGOAT_PATH)) {
    logger.error('NodeGoat not found at expected path');
    logger.info('Please ensure NodeGoat is cloned to scripts/nodegoat-test/');
    process.exit(1);
  }
  
  // For this demo, we'll scan specific vulnerable files we know about
  const vulnerableFiles = [
    'app/routes/allocations.js',
    'app/routes/profile.js', 
    'app/routes/contributions.js',
    'app/routes/memos.js',
    'app/routes/benefits.js',
    'app/data/user-dao.js',
    'server.js'
  ];
  
  logger.info(`\nScanning ${vulnerableFiles.length} known vulnerable files...`);
  
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
        
        // Show first few vulnerabilities
        const sample = vulnerabilities.slice(0, 2);
        for (const vuln of sample) {
          logger.info(`      - Line ${vuln.line}: ${vuln.type} - ${vuln.description}`);
        }
        
        if (vulnerabilities.length > 2) {
          logger.info(`      ... and ${vulnerabilities.length - 2} more`);
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
      acc[vuln.type] = { count: 0, files: new Set() };
    }
    acc[vuln.type].count++;
    acc[vuln.type].files.add(vuln.filePath);
    return acc;
  }, {} as Record<string, { count: number; files: Set<string> }>);
  
  logger.info('\n\n📊 SCAN SUMMARY');
  logger.info('═'.repeat(60));
  logger.info(`Total vulnerabilities found: ${totalVulnerabilities}`);
  logger.info(`Files with vulnerabilities: ${new Set(allVulnerabilities.map(v => v.filePath)).size}`);
  logger.info('\nVulnerabilities by type:');
  
  for (const [type, data] of Object.entries(byType)) {
    logger.info(`  • ${type}: ${data.count} instances in ${data.files.size} files`);
  }
  
  logger.info('\n💡 In production, RSOLV would:');
  logger.info('  1. Create GitHub issues for each vulnerability type');
  logger.info('  2. Group similar vulnerabilities together');
  logger.info('  3. Add detailed descriptions and remediation steps');
  logger.info('  4. Label issues for automatic processing');
  logger.info('  5. Generate fix PRs when issues are processed');
  
  logger.info('\n🚀 This demonstrates RSOLV\'s proactive "find and fix" workflow!');
}

// Run the scan
scanNodeGoat().catch(error => {
  logger.error('Scan failed:', error);
  process.exit(1);
});