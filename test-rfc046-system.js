#!/usr/bin/env node

/**
 * System test for RFC-046: Multi-file Vulnerability Chunking
 */

import { ChunkingIntegration } from './dist/chunking/index.js';

const DOS_VULNERABILITY = {
  type: 'DENIAL_OF_SERVICE',
  issueNumber: 325,
  severity: 'HIGH',
  files: [
    { path: 'app/routes/index.js', lines: [45, 89, 123], severity: 'HIGH' },
    { path: 'app/routes/contributions.js', lines: [23], severity: 'HIGH' },
    { path: 'app/routes/admin.js', lines: [67, 91], severity: 'CRITICAL' },
    { path: 'app/routes/profile.js', lines: [34], severity: 'MEDIUM' },
    { path: 'app/views/index.html', lines: [12], severity: 'LOW' },
    { path: 'app/views/contributions.html', lines: [45], severity: 'LOW' },
    { path: 'app/views/admin.html', lines: [78], severity: 'MEDIUM' },
    { path: 'app/views/profile.html', lines: [90], severity: 'LOW' },
    { path: 'app/data/user-dao.js', lines: [234, 456], severity: 'HIGH' },
    { path: 'app/data/allocations-dao.js', lines: [123], severity: 'MEDIUM' },
    { path: 'app/data/benefits-dao.js', lines: [89], severity: 'MEDIUM' },
    { path: 'server.js', lines: [45], severity: 'CRITICAL' },
    { path: 'config/config.js', lines: [12], severity: 'HIGH' },
    { path: 'test/e2e.js', lines: [567], severity: 'LOW' }
  ]
};

const HARDCODED_SECRET = {
  type: 'HARDCODED_SECRETS',
  issueNumber: 324,
  severity: 'CRITICAL',
  requiresConfigChange: true,
  requiresNewDependencies: true,
  files: [
    { path: 'config/env.js', lines: [42], severity: 'CRITICAL' }
  ]
};

async function runTests() {
  console.log('🧪 RFC-046 System Test: Multi-file Vulnerability Chunking\n');
  console.log('=' . repeat(60));
  
  const integration = new ChunkingIntegration();
  const results = [];
  
  // Test 1: DoS with 14 files
  console.log('\n📋 Test 1: Denial of Service (14 files)');
  console.log('-'.repeat(40));
  
  try {
    const shouldChunk = integration.shouldChunk(DOS_VULNERABILITY);
    console.log(`  Should chunk: ${shouldChunk ? '✅ YES' : '❌ NO'}`);
    
    if (shouldChunk) {
      const result = await integration.processWithChunking(DOS_VULNERABILITY, 325);
      console.log(`  Chunks created: ${result.chunks || 0}`);
      console.log(`  PRs generated: ${result.prs?.length || 0}`);
      console.log(`  Complexity: ${result.complexity}`);
      
      if (result.prs && result.prs.length > 0) {
        console.log('\n  PR Series:');
        result.prs.forEach((pr, i) => {
          console.log(`    ${i + 1}. ${pr.title}`);
          console.log(`       Branch: ${pr.branch}`);
          console.log(`       Files: ${pr.files.length}`);
        });
      }
      
      results.push({
        test: 'DoS Chunking',
        success: result.chunks === 5 && result.prs?.length === 5,
        chunks: result.chunks,
        prs: result.prs?.length
      });
    }
  } catch (error) {
    console.log(`  ❌ ERROR: ${error.message}`);
    results.push({
      test: 'DoS Chunking',
      success: false,
      error: error.message
    });
  }
  
  // Test 2: Hardcoded Secrets (Complex)
  console.log('\n📋 Test 2: Hardcoded Secrets (Complex)');
  console.log('-'.repeat(40));
  
  try {
    const isComplex = integration.isComplexVulnerability(HARDCODED_SECRET);
    console.log(`  Is complex: ${isComplex ? '✅ YES' : '❌ NO'}`);
    
    const result = await integration.processWithChunking(HARDCODED_SECRET, 324);
    console.log(`  Requires manual: ${result.requiresManual ? '✅ YES' : '❌ NO'}`);
    console.log(`  Complexity: ${result.complexity}`);
    
    if (result.guide) {
      console.log('\n  Manual Guide Preview:');
      const guideLines = result.guide.split('\n').slice(0, 5);
      guideLines.forEach(line => console.log(`    ${line}`));
      console.log('    ...');
    }
    
    results.push({
      test: 'Complex Secret Handling',
      success: result.requiresManual === true && result.complexity === 'manual',
      requiresManual: result.requiresManual,
      complexity: result.complexity
    });
  } catch (error) {
    console.log(`  ❌ ERROR: ${error.message}`);
    results.push({
      test: 'Complex Secret Handling',
      success: false,
      error: error.message
    });
  }
  
  // Test 3: Chunking Strategies
  console.log('\n📋 Test 3: Chunking Strategies');
  console.log('-'.repeat(40));
  
  const { VulnerabilityChunker } = await import('./dist/chunking/vulnerability-chunker.js');
  const chunker = new VulnerabilityChunker({
    enabled: true,
    maxFilesPerChunk: 3,
    maxLinesPerChunk: 500,
    maxContextTokens: 8000,
    strategies: ['module_grouping']
  });
  
  const chunks = await chunker.chunkVulnerability(DOS_VULNERABILITY);
  console.log(`  Module-based chunks: ${chunks.length}`);
  
  // Check if routes are grouped together
  const routeChunk = chunks.find(c => 
    c.files.some(f => f.path.includes('routes/index'))
  );
  const hasGroupedRoutes = routeChunk?.files.filter(f => 
    f.path.includes('routes/')
  ).length > 1;
  
  console.log(`  Routes grouped: ${hasGroupedRoutes ? '✅ YES' : '❌ NO'}`);
  
  results.push({
    test: 'Module Grouping Strategy',
    success: hasGroupedRoutes,
    chunks: chunks.length
  });
  
  // Summary
  console.log('\n' + '='.repeat(60));
  console.log('📊 TEST SUMMARY\n');
  
  const successful = results.filter(r => r.success).length;
  const failed = results.filter(r => !r.success).length;
  
  console.log(`Total tests: ${results.length}`);
  console.log(`✅ Successful: ${successful}`);
  console.log(`❌ Failed: ${failed}`);
  console.log(`Success rate: ${((successful / results.length) * 100).toFixed(1)}%`);
  
  console.log('\n🔍 Key Validations:');
  console.log(`  1. DoS vulnerability chunked properly: ${results[0]?.success ? '✅ PASS' : '❌ FAIL'}`);
  console.log(`  2. Complex vulnerabilities routed to manual: ${results[1]?.success ? '✅ PASS' : '❌ FAIL'}`);
  console.log(`  3. Module grouping strategy works: ${results[2]?.success ? '✅ PASS' : '❌ FAIL'}`);
  
  console.log('\n✨ RFC-046 System Test Complete!\n');
  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch(console.error);