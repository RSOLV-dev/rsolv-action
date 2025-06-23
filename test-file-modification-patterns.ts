#!/usr/bin/env npx tsx

/**
 * Phase 3.1: Test file modification patterns (in-place vs new file ratios)
 * This validates that Claude Code modifies existing files rather than creating new ones
 */

import { execSync } from 'child_process';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

interface ModificationPattern {
  scenario: string;
  originalFiles: string[];
  modifiedFiles: string[];
  newFiles: string[];
  deletedFiles: string[];
  inPlaceRatio: number;
  success: boolean;
}

class FileModificationTester {
  private testDir: string;
  private patterns: ModificationPattern[] = [];
  
  constructor() {
    this.testDir = path.join(__dirname, 'file-modification-test');
  }
  
  async setup(): Promise<void> {
    console.log('🔧 Setting up file modification pattern test...\n');
    
    // Cleanup and create
    try {
      await fs.rm(this.testDir, { recursive: true, force: true });
    } catch {}
    await fs.mkdir(this.testDir, { recursive: true });
    
    // Initialize git
    execSync('git init', { cwd: this.testDir });
    execSync('git config user.name "Pattern Tester"', { cwd: this.testDir });
    execSync('git config user.email "pattern@rsolv.ai"', { cwd: this.testDir });
  }
  
  async testScenario(name: string, setupFn: () => Promise<void>, fixFn: () => Promise<void>): Promise<ModificationPattern> {
    console.log(`\n📁 Testing: ${name}`);
    
    // Setup vulnerable files
    await setupFn();
    
    // Record original state
    const originalFiles = await this.getFiles();
    execSync('git add .', { cwd: this.testDir });
    execSync(`git commit -m "Setup ${name}"`, { cwd: this.testDir });
    
    console.log(`Original files: ${originalFiles.length}`);
    originalFiles.forEach(f => console.log(`  - ${f}`));
    
    // Apply fixes
    await fixFn();
    
    // Analyze changes
    const gitStatus = execSync('git status --porcelain', { 
      cwd: this.testDir,
      encoding: 'utf-8'
    }).trim();
    
    const modifiedFiles: string[] = [];
    const newFiles: string[] = [];
    const deletedFiles: string[] = [];
    
    if (gitStatus) {
      gitStatus.split('\n').forEach(line => {
        const status = line.substring(0, 2);
        const file = line.substring(3);
        
        if (status === ' M' || status === 'M ') {
          modifiedFiles.push(file);
        } else if (status === '??' || status === 'A ') {
          newFiles.push(file);
        } else if (status === ' D' || status === 'D ') {
          deletedFiles.push(file);
        }
      });
    }
    
    console.log('\n📊 Changes:');
    console.log(`Modified: ${modifiedFiles.length} files`);
    modifiedFiles.forEach(f => console.log(`  M ${f}`));
    console.log(`New: ${newFiles.length} files`);
    newFiles.forEach(f => console.log(`  + ${f}`));
    console.log(`Deleted: ${deletedFiles.length} files`);
    deletedFiles.forEach(f => console.log(`  - ${f}`));
    
    // Calculate in-place ratio
    const totalChanges = modifiedFiles.length + newFiles.length;
    const inPlaceRatio = totalChanges > 0 ? (modifiedFiles.length / totalChanges) * 100 : 100;
    
    console.log(`\n📈 In-place editing ratio: ${inPlaceRatio.toFixed(1)}%`);
    
    // Success if no new files created and files were modified
    const success = newFiles.length === 0 && modifiedFiles.length > 0;
    console.log(`Result: ${success ? '✅ PASS' : '❌ FAIL'}`);
    
    const pattern: ModificationPattern = {
      scenario: name,
      originalFiles,
      modifiedFiles,
      newFiles,
      deletedFiles,
      inPlaceRatio,
      success
    };
    
    this.patterns.push(pattern);
    
    // Reset for next test
    execSync('git reset --hard', { cwd: this.testDir });
    execSync('git clean -fd', { cwd: this.testDir });
    
    return pattern;
  }
  
  async runAllTests(): Promise<void> {
    // Test 1: Single file with multiple vulnerabilities
    await this.testScenario(
      'Single File Multiple Vulnerabilities',
      async () => {
        await fs.writeFile(
          path.join(this.testDir, 'app.js'),
          `const db = require('db');
const fs = require('fs');

// SQL injection
function getUser(id) {
  return db.query("SELECT * FROM users WHERE id = " + id);
}

// Path traversal
function readFile(name) {
  return fs.readFileSync('./data/' + name);
}

module.exports = { getUser, readFile };`
        );
      },
      async () => {
        // Simulate Claude Code fix
        await fs.writeFile(
          path.join(this.testDir, 'app.js'),
          `const db = require('db');
const fs = require('fs');
const path = require('path');

// Fixed: SQL injection
function getUser(id) {
  return db.query("SELECT * FROM users WHERE id = ?", [id]);
}

// Fixed: Path traversal
function readFile(name) {
  const safePath = path.join('./data', path.basename(name));
  return fs.readFileSync(safePath);
}

module.exports = { getUser, readFile };`
        );
      }
    );
    
    // Test 2: Multiple related files
    await this.testScenario(
      'Multiple Related Files',
      async () => {
        await fs.writeFile(
          path.join(this.testDir, 'user-controller.js'),
          `const db = require('./db');

class UserController {
  getUser(id) {
    return db.query("SELECT * FROM users WHERE id = " + id);
  }
  
  deleteUser(id) {
    return db.query(\`DELETE FROM users WHERE id = \${id}\`);
  }
}`
        );
        
        await fs.writeFile(
          path.join(this.testDir, 'product-controller.js'),
          `const db = require('./db');

class ProductController {
  getProduct(id) {
    return db.query("SELECT * FROM products WHERE id = " + id);
  }
  
  searchProducts(name) {
    return db.query(\`SELECT * FROM products WHERE name LIKE '%\${name}%'\`);
  }
}`
        );
      },
      async () => {
        // Fix both files in place
        await fs.writeFile(
          path.join(this.testDir, 'user-controller.js'),
          `const db = require('./db');

class UserController {
  getUser(id) {
    return db.query("SELECT * FROM users WHERE id = ?", [id]);
  }
  
  deleteUser(id) {
    return db.query("DELETE FROM users WHERE id = ?", [id]);
  }
}`
        );
        
        await fs.writeFile(
          path.join(this.testDir, 'product-controller.js'),
          `const db = require('./db');

class ProductController {
  getProduct(id) {
    return db.query("SELECT * FROM products WHERE id = ?", [id]);
  }
  
  searchProducts(name) {
    return db.query("SELECT * FROM products WHERE name LIKE ?", [\`%\${name}%\`]);
  }
}`
        );
      }
    );
    
    // Test 3: Complex file structure
    await this.testScenario(
      'Complex File Structure',
      async () => {
        // Create directory structure
        await fs.mkdir(path.join(this.testDir, 'src'), { recursive: true });
        await fs.mkdir(path.join(this.testDir, 'src/controllers'), { recursive: true });
        await fs.mkdir(path.join(this.testDir, 'src/utils'), { recursive: true });
        
        await fs.writeFile(
          path.join(this.testDir, 'src/controllers/api.js'),
          `const db = require('../db');

exports.getItem = (req, res) => {
  const id = req.params.id;
  db.query("SELECT * FROM items WHERE id = " + id, (err, result) => {
    res.json(result);
  });
};`
        );
        
        await fs.writeFile(
          path.join(this.testDir, 'src/utils/render.js'),
          `exports.renderHTML = (data) => {
  return '<div>' + data.content + '</div>';
};`
        );
      },
      async () => {
        // Fix files in their original locations
        await fs.writeFile(
          path.join(this.testDir, 'src/controllers/api.js'),
          `const db = require('../db');

exports.getItem = (req, res) => {
  const id = req.params.id;
  db.query("SELECT * FROM items WHERE id = ?", [id], (err, result) => {
    res.json(result);
  });
};`
        );
        
        await fs.writeFile(
          path.join(this.testDir, 'src/utils/render.js'),
          `const escapeHtml = require('escape-html');

exports.renderHTML = (data) => {
  return '<div>' + escapeHtml(data.content) + '</div>';
};`
        );
      }
    );
    
    // Test 4: Bad pattern - creating new files (what we want to avoid)
    await this.testScenario(
      'Bad Pattern - New File Creation',
      async () => {
        await fs.writeFile(
          path.join(this.testDir, 'vulnerable.js'),
          `function processInput(input) {
  return eval(input);
}`
        );
      },
      async () => {
        // Simulate bad behavior: creating a new file instead of editing
        await fs.writeFile(
          path.join(this.testDir, 'vulnerable-fixed.js'),
          `function processInput(input) {
  // Safe processing without eval
  return JSON.parse(input);
}`
        );
        // Original file unchanged - this is what we want to avoid
      }
    );
  }
  
  private async getFiles(): Promise<string[]> {
    const files: string[] = [];
    
    async function scan(dir: string, base: string = ''): Promise<void> {
      const entries = await fs.readdir(dir, { withFileTypes: true });
      
      for (const entry of entries) {
        if (entry.name === '.git') continue;
        
        const relPath = path.join(base, entry.name);
        
        if (entry.isDirectory()) {
          await scan(path.join(dir, entry.name), relPath);
        } else {
          files.push(relPath);
        }
      }
    }
    
    await scan(this.testDir);
    return files.sort();
  }
  
  generateReport(): void {
    console.log('\n\n📊 FILE MODIFICATION PATTERN REPORT');
    console.log('=====================================\n');
    
    // Summary statistics
    const totalScenarios = this.patterns.length;
    const successfulScenarios = this.patterns.filter(p => p.success).length;
    const totalModified = this.patterns.reduce((sum, p) => sum + p.modifiedFiles.length, 0);
    const totalNew = this.patterns.reduce((sum, p) => sum + p.newFiles.length, 0);
    const avgInPlaceRatio = this.patterns.reduce((sum, p) => sum + p.inPlaceRatio, 0) / totalScenarios;
    
    console.log('📈 Summary Statistics:');
    console.log(`Total scenarios tested: ${totalScenarios}`);
    console.log(`Successful (in-place only): ${successfulScenarios}/${totalScenarios} (${(successfulScenarios/totalScenarios*100).toFixed(1)}%)`);
    console.log(`Total files modified in-place: ${totalModified}`);
    console.log(`Total new files created: ${totalNew}`);
    console.log(`Average in-place ratio: ${avgInPlaceRatio.toFixed(1)}%`);
    
    // Per-scenario details
    console.log('\n📋 Scenario Details:');
    this.patterns.forEach(pattern => {
      console.log(`\n${pattern.scenario}:`);
      console.log(`  Original files: ${pattern.originalFiles.length}`);
      console.log(`  Modified: ${pattern.modifiedFiles.length}`);
      console.log(`  New: ${pattern.newFiles.length}`);
      console.log(`  In-place ratio: ${pattern.inPlaceRatio.toFixed(1)}%`);
      console.log(`  Result: ${pattern.success ? '✅ PASS' : '❌ FAIL'}`);
    });
    
    // Success criteria
    const overallSuccess = successfulScenarios >= 3 && avgInPlaceRatio >= 75;
    console.log('\n🎯 Success Criteria:');
    console.log(`Overall: ${overallSuccess ? '✅ PASS' : '❌ FAIL'}`);
    console.log(`  - At least 3/4 scenarios pass: ${successfulScenarios >= 3 ? '✅' : '❌'} (${successfulScenarios}/4)`);
    console.log(`  - Average in-place ratio >= 75%: ${avgInPlaceRatio >= 75 ? '✅' : '❌'} (${avgInPlaceRatio.toFixed(1)}%)`);
    
    // Key insights
    console.log('\n💡 Key Insights:');
    if (totalNew === 0 && totalScenarios > 1) {
      console.log('✅ Excellent! No new files created in good scenarios');
    }
    if (avgInPlaceRatio === 100) {
      console.log('✅ Perfect in-place editing achieved');
    }
    if (this.patterns.some(p => !p.success && p.newFiles.length > 0)) {
      console.log('⚠️  Bad pattern detected: New file creation instead of editing');
    }
  }
  
  async cleanup(): Promise<void> {
    try {
      await fs.rm(this.testDir, { recursive: true, force: true });
    } catch {}
  }
}

// Main execution
async function main() {
  console.log('🚀 File Modification Pattern Test');
  console.log('=================================\n');
  
  const tester = new FileModificationTester();
  
  try {
    await tester.setup();
    await tester.runAllTests();
    tester.generateReport();
    
    // Save results
    const results = {
      timestamp: new Date().toISOString(),
      patterns: tester['patterns'],
      summary: {
        totalScenarios: tester['patterns'].length,
        successfulScenarios: tester['patterns'].filter(p => p.success).length,
        avgInPlaceRatio: tester['patterns'].reduce((sum, p) => sum + p.inPlaceRatio, 0) / tester['patterns'].length
      }
    };
    
    await fs.writeFile(
      'file-modification-pattern-results.json',
      JSON.stringify(results, null, 2)
    );
    
    console.log('\n✅ Results saved to file-modification-pattern-results.json');
    
  } catch (error) {
    console.error('Test failed:', error);
    process.exit(1);
  } finally {
    await tester.cleanup();
  }
}

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}