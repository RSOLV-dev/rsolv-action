#!/usr/bin/env npx tsx

/**
 * Test git commit creation and branch management
 * This validates the git-based workflow for in-place editing
 */

import { execSync } from 'child_process';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

interface GitTestResult {
  phase: string;
  success: boolean;
  details: any;
  error?: string;
}

class GitWorkflowTester {
  private testRepoPath: string;
  private originPath: string;
  private results: GitTestResult[] = [];
  
  constructor() {
    this.testRepoPath = path.join(__dirname, 'test-git-workflow-repo');
    this.originPath = path.join(__dirname, 'test-git-origin.git');
  }
  
  async setup(): Promise<void> {
    console.log('🔧 Setting up test environment...\n');
    
    // Cleanup if exists
    try {
      await fs.rm(this.testRepoPath, { recursive: true, force: true });
      await fs.rm(this.originPath, { recursive: true, force: true });
    } catch {}
    
    // Create test repo
    await fs.mkdir(this.testRepoPath, { recursive: true });
    
    // Initialize repo
    this.exec('git init', this.testRepoPath);
    this.exec('git config user.name "RSOLV Bot"', this.testRepoPath);
    this.exec('git config user.email "bot@rsolv.ai"', this.testRepoPath);
    
    // Create initial files
    const vulnerableCode = `const express = require('express');
const db = require('./db');

// User API endpoints
app.get('/api/user/:id', (req, res) => {
  const userId = req.params.id;
  // VULNERABILITY: SQL injection
  const query = "SELECT * FROM users WHERE id = " + userId;
  
  db.query(query, (err, results) => {
    if (err) {
      console.error('Database error:', err);
      res.status(500).json({ error: 'Internal error' });
    } else {
      res.json(results[0] || null);
    }
  });
});

app.post('/api/user/search', (req, res) => {
  const { name } = req.body;
  // VULNERABILITY: SQL injection in LIKE query
  const searchQuery = \`SELECT * FROM users WHERE name LIKE '%\${name}%'\`;
  
  db.query(searchQuery, (err, results) => {
    if (err) {
      res.status(500).json({ error: 'Search failed' });
    } else {
      res.json(results);
    }
  });
});
`;
    
    await fs.writeFile(
      path.join(this.testRepoPath, 'user-api.js'),
      vulnerableCode
    );
    
    // Initial commit
    this.exec('git add .', this.testRepoPath);
    this.exec('git commit -m "Initial commit with vulnerable code"', this.testRepoPath);
    
    // Create bare origin
    this.exec(`git init --bare ${this.originPath}`);
    this.exec(`git remote add origin ${this.originPath}`, this.testRepoPath);
    this.exec('git push -u origin main', this.testRepoPath);
    
    console.log('✅ Test environment ready\n');
  }
  
  async testPhase1_FileModification(): Promise<void> {
    console.log('📝 Phase 1: Testing file modification (simulating Claude Code edits)...\n');
    
    try {
      // Simulate Claude Code fixing the vulnerabilities
      const fixedCode = `const express = require('express');
const db = require('./db');

// User API endpoints
app.get('/api/user/:id', (req, res) => {
  const userId = req.params.id;
  // FIXED: Using parameterized query
  const query = "SELECT * FROM users WHERE id = ?";
  
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      res.status(500).json({ error: 'Internal error' });
    } else {
      res.json(results[0] || null);
    }
  });
});

app.post('/api/user/search', (req, res) => {
  const { name } = req.body;
  // FIXED: Using parameterized query with LIKE
  const searchQuery = "SELECT * FROM users WHERE name LIKE ?";
  const searchParam = \`%\${name}%\`;
  
  db.query(searchQuery, [searchParam], (err, results) => {
    if (err) {
      res.status(500).json({ error: 'Search failed' });
    } else {
      res.json(results);
    }
  });
});
`;
      
      await fs.writeFile(
        path.join(this.testRepoPath, 'user-api.js'),
        fixedCode
      );
      
      // Check git detected changes
      const status = this.exec('git status --porcelain', this.testRepoPath);
      console.log('Git status:', status || '(no output)');
      
      // Get diff stats
      const diff = this.exec('git diff --stat', this.testRepoPath);
      console.log('\nDiff statistics:\n', diff);
      
      // Verify the fix
      const diffContent = this.exec('git diff', this.testRepoPath);
      const hasParameterizedQueries = diffContent.includes('?') && diffContent.includes('[userId]');
      
      this.results.push({
        phase: 'File Modification',
        success: hasParameterizedQueries,
        details: {
          filesModified: status.split('\n').filter(l => l.trim()).length,
          fixApplied: hasParameterizedQueries
        }
      });
      
      console.log(`\n✅ File modification: ${hasParameterizedQueries ? 'PASS' : 'FAIL'}\n`);
      
    } catch (error) {
      this.results.push({
        phase: 'File Modification',
        success: false,
        details: {},
        error: error.message
      });
      console.error('❌ File modification failed:', error.message);
    }
  }
  
  async testPhase2_CommitCreation(): Promise<string | null> {
    console.log('💾 Phase 2: Testing commit creation...\n');
    
    try {
      // Stage changes
      this.exec('git add user-api.js', this.testRepoPath);
      
      // Create commit with detailed message
      const commitMessage = `Fix SQL injection vulnerabilities in user API

- Replaced string concatenation with parameterized queries
- Fixed SQL injection in user lookup endpoint
- Fixed SQL injection in user search endpoint
- Used proper parameter binding for LIKE queries

This prevents malicious SQL injection attacks while maintaining
the same functionality.

Fixes #123

Automatically generated by RSOLV`;
      
      this.exec(`git commit -m "${commitMessage}"`, this.testRepoPath);
      
      // Get commit hash
      const commitHash = this.exec('git rev-parse HEAD', this.testRepoPath).trim();
      console.log('Created commit:', commitHash.substring(0, 8));
      
      // Show commit details
      const commitInfo = this.exec('git show --stat HEAD', this.testRepoPath);
      console.log('\nCommit details:\n', commitInfo);
      
      // Get diff stats
      const stats = this.exec('git diff HEAD~1 --numstat', this.testRepoPath);
      const [additions, deletions] = stats.split('\t').map(n => parseInt(n) || 0);
      
      this.results.push({
        phase: 'Commit Creation',
        success: true,
        details: {
          commitHash,
          additions,
          deletions,
          message: commitMessage.split('\n')[0]
        }
      });
      
      console.log('\n✅ Commit creation: PASS\n');
      return commitHash;
      
    } catch (error) {
      this.results.push({
        phase: 'Commit Creation',
        success: false,
        details: {},
        error: error.message
      });
      console.error('❌ Commit creation failed:', error.message);
      return null;
    }
  }
  
  async testPhase3_BranchManagement(commitHash: string): Promise<string | null> {
    console.log('🌿 Phase 3: Testing branch management...\n');
    
    try {
      const branchName = 'rsolv/fix-issue-123';
      
      // Create branch from commit
      console.log(`Creating branch ${branchName} from ${commitHash.substring(0, 8)}...`);
      this.exec(`git checkout -b ${branchName} ${commitHash}`, this.testRepoPath);
      
      // Verify branch
      const currentBranch = this.exec('git branch --show-current', this.testRepoPath).trim();
      console.log('Current branch:', currentBranch);
      
      if (currentBranch !== branchName) {
        throw new Error(`Expected branch ${branchName}, got ${currentBranch}`);
      }
      
      // Push branch
      console.log('\nPushing branch to origin...');
      this.exec(`git push origin ${branchName}`, this.testRepoPath);
      
      // Verify push
      const remoteBranches = this.exec('git ls-remote origin refs/heads/*', this.testRepoPath);
      console.log('\nRemote branches:');
      remoteBranches.split('\n').forEach(line => {
        if (line.trim()) {
          const [hash, ref] = line.split('\t');
          console.log(`  ${ref.replace('refs/heads/', '')}: ${hash.substring(0, 8)}`);
        }
      });
      
      // Switch back to main
      console.log('\nSwitching back to main...');
      this.exec('git checkout main', this.testRepoPath);
      
      const finalBranch = this.exec('git branch --show-current', this.testRepoPath).trim();
      console.log('Final branch:', finalBranch);
      
      this.results.push({
        phase: 'Branch Management',
        success: finalBranch === 'main',
        details: {
          branchName,
          pushedToOrigin: true,
          returnedToMain: finalBranch === 'main'
        }
      });
      
      console.log('\n✅ Branch management: PASS\n');
      return branchName;
      
    } catch (error) {
      this.results.push({
        phase: 'Branch Management',
        success: false,
        details: {},
        error: error.message
      });
      console.error('❌ Branch management failed:', error.message);
      return null;
    }
  }
  
  async testPhase4_PRSimulation(branchName: string): Promise<void> {
    console.log('🔀 Phase 4: Simulating PR creation readiness...\n');
    
    try {
      // Get diff between branch and main
      const diffSummary = this.exec(
        `git diff main..origin/${branchName} --stat`,
        this.testRepoPath
      );
      console.log('PR diff summary:\n', diffSummary);
      
      // Simulate PR metadata
      const prData = {
        title: '[RSOLV] Fix SQL injection vulnerabilities in user API (fixes #123)',
        base: 'main',
        head: branchName,
        body: `# Fix SQL injection vulnerabilities in user API

**Fixes:** #123

## Summary
Fixed SQL injection vulnerabilities by replacing string concatenation with parameterized queries.

## Changes Made
- **Files Changed:** 1
- **Lines Added:** 4
- **Lines Removed:** 2

## Security Details
- **Vulnerability Type:** SQL Injection
- **Severity:** HIGH
- **CWE:** CWE-89

## Security Impact
This fix prevents SQL injection attacks by using parameterized queries instead of string concatenation.`
      };
      
      console.log('\nPR metadata:');
      console.log(`Title: ${prData.title}`);
      console.log(`Base: ${prData.base}`);
      console.log(`Head: ${prData.head}`);
      console.log('\nPR would be ready for creation ✅');
      
      this.results.push({
        phase: 'PR Readiness',
        success: true,
        details: {
          title: prData.title,
          base: prData.base,
          head: prData.head,
          ready: true
        }
      });
      
    } catch (error) {
      this.results.push({
        phase: 'PR Readiness',
        success: false,
        details: {},
        error: error.message
      });
      console.error('❌ PR simulation failed:', error.message);
    }
  }
  
  async cleanup(): Promise<void> {
    console.log('🧹 Cleaning up...\n');
    try {
      await fs.rm(this.testRepoPath, { recursive: true, force: true });
      await fs.rm(this.originPath, { recursive: true, force: true });
    } catch {}
  }
  
  generateReport(): void {
    console.log('📊 Git Workflow Test Report');
    console.log('===========================\n');
    
    let passed = 0;
    let failed = 0;
    
    this.results.forEach(result => {
      const status = result.success ? '✅ PASS' : '❌ FAIL';
      console.log(`${result.phase}: ${status}`);
      
      if (result.details) {
        Object.entries(result.details).forEach(([key, value]) => {
          console.log(`  ${key}: ${value}`);
        });
      }
      
      if (result.error) {
        console.log(`  Error: ${result.error}`);
      }
      
      console.log('');
      
      if (result.success) passed++;
      else failed++;
    });
    
    console.log(`Summary: ${passed} passed, ${failed} failed`);
    console.log(`Overall: ${failed === 0 ? '✅ ALL TESTS PASSED' : '❌ SOME TESTS FAILED'}`);
  }
  
  private exec(command: string, cwd?: string): string {
    return execSync(command, {
      cwd: cwd || process.cwd(),
      encoding: 'utf-8'
    }).trim();
  }
}

// Main test runner
async function main() {
  console.log('🚀 Git Operations Test Suite');
  console.log('============================\n');
  
  const tester = new GitWorkflowTester();
  
  try {
    await tester.setup();
    await tester.testPhase1_FileModification();
    
    const commitHash = await tester.testPhase2_CommitCreation();
    if (commitHash) {
      const branchName = await tester.testPhase3_BranchManagement(commitHash);
      if (branchName) {
        await tester.testPhase4_PRSimulation(branchName);
      }
    }
    
    tester.generateReport();
    
    // Save results
    const results = {
      timestamp: new Date().toISOString(),
      results: tester['results']
    };
    
    await fs.writeFile(
      'git-operations-test-results.json',
      JSON.stringify(results, null, 2)
    );
    
  } catch (error) {
    console.error('Test suite failed:', error);
    process.exit(1);
  } finally {
    await tester.cleanup();
  }
}

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}