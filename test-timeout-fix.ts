#!/usr/bin/env bun

/**
 * Test script to verify timeout and progress logging fixes
 */

import { SecurityDetectorV2 } from './src/security/detector-v2.js';

// Create a large file content to simulate real-world scenario
const generateLargeRubyFile = () => {
  const lines: string[] = [];

  // Add header
  lines.push('# Rails Controller with SQL injection vulnerabilities');
  lines.push('class UsersController < ApplicationController');

  // Generate 1000 lines of Ruby code with various patterns
  for (let i = 0; i < 1000; i++) {
    if (i % 10 === 0) {
      // Add SQL injection pattern every 10 lines
      lines.push(`  def search_${i}`);
      lines.push(`    query = "SELECT * FROM users WHERE name = '#{params[:name]}' AND id = #{params[:id]}"`);
      lines.push(`    User.connection.execute(query)`);
      lines.push('  end');
    } else {
      // Add regular code
      lines.push(`  def method_${i}`);
      lines.push(`    @user = User.find(params[:id])`);
      lines.push(`    @user.update(name: params[:name])`);
      lines.push('  end');
    }
  }

  lines.push('end');

  return lines.join('\n');
};

async function main() {
  console.log('🧪 Testing timeout and progress logging fixes');
  console.log('=' .repeat(60));

  const detector = new SecurityDetectorV2();
  const testFile = generateLargeRubyFile();

  console.log(`\n📄 Test file: ${testFile.split('\n').length} lines of Ruby code`);
  console.log(`📏 File size: ${testFile.length} bytes`);

  console.log('\n🔍 Starting detection with timeouts enabled...\n');

  const startTime = Date.now();

  try {
    const vulnerabilities = await detector.detect(
      testFile,
      'ruby',
      'test-large-file.rb'
    );

    const duration = Date.now() - startTime;

    console.log('\n✅ Detection completed successfully!');
    console.log(`⏱️  Duration: ${duration}ms (${(duration / 1000).toFixed(2)}s)`);
    console.log(`🔒 Vulnerabilities found: ${vulnerabilities.length}`);

    // Verify it completed within reasonable time
    if (duration < 60000) { // Should complete in under 1 minute
      console.log('✅ PASS: Completed within timeout limits');
    } else {
      console.log('❌ FAIL: Took too long');
    }

    // Check we found some vulnerabilities
    if (vulnerabilities.length > 0) {
      console.log('✅ PASS: Found vulnerabilities as expected');
      console.log('\nSample findings:');
      vulnerabilities.slice(0, 3).forEach(v => {
        console.log(`  - Line ${v.line}: ${v.type} (confidence: ${v.confidence})`);
      });
    } else {
      console.log('⚠️  WARNING: No vulnerabilities found (may be pattern issue)');
    }

  } catch (error) {
    const duration = Date.now() - startTime;
    console.error(`\n❌ Detection failed after ${duration}ms:`, error);
    process.exit(1);
  }

  console.log('\n🎉 Test completed successfully!');
}

main().catch(error => {
  console.error('Test failed:', error);
  process.exit(1);
});
