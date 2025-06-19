#!/usr/bin/env bun

// Script to find which test files are causing global state pollution

import { $ } from 'bun';
import { existsSync } from 'fs';
import { readdir } from 'fs/promises';
import { join } from 'path';

async function findTestFiles(dir: string): Promise<string[]> {
  const files: string[] = [];
  const entries = await readdir(dir, { withFileTypes: true });
  
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory() && !entry.name.includes('node_modules')) {
      files.push(...await findTestFiles(fullPath));
    } else if (entry.isFile() && entry.name.endsWith('.test.ts')) {
      files.push(fullPath);
    }
  }
  
  return files;
}

async function runTest(file: string): Promise<{ file: string; passed: boolean; output: string }> {
  try {
    const result = await $`bun test ${file} 2>&1`.quiet();
    const output = result.text();
    const passed = result.exitCode === 0;
    return { file, passed, output };
  } catch (error) {
    return { file, passed: false, output: error.toString() };
  }
}

async function main() {
  const testFiles = [
    ...await findTestFiles('src'),
    ...await findTestFiles('tests')
  ];
  
  console.log(`Found ${testFiles.length} test files`);
  
  // Run tests individually
  const results = [];
  for (const file of testFiles) {
    process.stdout.write(`Testing ${file}... `);
    const result = await runTest(file);
    console.log(result.passed ? '✅' : '❌');
    results.push(result);
  }
  
  // Find tests that fail
  const failingTests = results.filter(r => !r.passed);
  
  console.log(`\n${failingTests.length} tests fail when run individually:`);
  failingTests.forEach(t => console.log(`  ❌ ${t.file}`));
  
  // Now run them all together
  console.log('\nRunning all tests together...');
  const allResult = await runTest(testFiles.join(' '));
  
  // Extract failure count from output
  const failMatch = allResult.output.match(/(\d+) fail/);
  const totalFailures = failMatch ? parseInt(failMatch[1]) : 0;
  
  console.log(`Total failures when run together: ${totalFailures}`);
  
  if (totalFailures > failingTests.length) {
    console.log(`\n⚠️  ${totalFailures - failingTests.length} additional tests fail due to interference!`);
  }
}

main().catch(console.error);