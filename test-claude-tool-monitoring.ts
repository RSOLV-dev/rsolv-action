#!/usr/bin/env npx tsx

/**
 * Phase 3.1: Monitor Claude Code tool usage patterns
 * This test validates that Claude Code prefers Edit/MultiEdit tools over Write
 * when fixing vulnerabilities in existing files
 */

import { query, type SDKMessage } from '@anthropic-ai/claude-code';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

interface ToolUsageStats {
  toolName: string;
  count: number;
  percentage: number;
  files: string[];
}

interface TestScenario {
  name: string;
  vulnerableFile: string;
  vulnerableCode: string;
  expectedTools: string[];
  description: string;
}

class ToolUsageMonitor {
  private scenarios: TestScenario[] = [
    {
      name: 'SQL Injection - Simple',
      vulnerableFile: 'simple-sql.js',
      vulnerableCode: `const db = require('./database');

function getUser(userId) {
  // VULNERABLE: Direct concatenation
  const query = "SELECT * FROM users WHERE id = " + userId;
  return db.query(query);
}

function deleteUser(userId) {
  // VULNERABLE: Template literal injection
  return db.query(\`DELETE FROM users WHERE id = \${userId}\`);
}

module.exports = { getUser, deleteUser };`,
      expectedTools: ['Read', 'Edit'],
      description: 'Simple SQL injection requiring parameterized queries'
    },
    {
      name: 'XSS - Multiple Functions',
      vulnerableFile: 'render-utils.js',
      vulnerableCode: `function renderUserName(user) {
  // VULNERABLE: Direct HTML injection
  return '<h1>Welcome ' + user.name + '</h1>';
}

function renderComment(comment) {
  // VULNERABLE: Unescaped content
  return \`<div class="comment">\${comment.text}</div>\`;
}

function renderProfile(data) {
  // VULNERABLE: Multiple injection points
  return \`
    <div class="profile">
      <h2>\${data.title}</h2>
      <p>\${data.bio}</p>
      <script>var prefs = \${JSON.stringify(data.prefs)};</script>
    </div>
  \`;
}

module.exports = { renderUserName, renderComment, renderProfile };`,
      expectedTools: ['Read', 'Edit', 'MultiEdit'],
      description: 'XSS vulnerabilities across multiple functions'
    },
    {
      name: 'Mixed Vulnerabilities',
      vulnerableFile: 'api-handler.js',
      vulnerableCode: `const fs = require('fs');
const { exec } = require('child_process');
const db = require('./db');

class APIHandler {
  // VULNERABLE: SQL injection
  async getProduct(productId) {
    const query = "SELECT * FROM products WHERE id = " + productId;
    return await db.query(query);
  }
  
  // VULNERABLE: Path traversal
  readFile(filename) {
    const path = './uploads/' + filename;
    return fs.readFileSync(path, 'utf8');
  }
  
  // VULNERABLE: Command injection
  createBackup(name) {
    exec('tar -czf backups/' + name + '.tar.gz ./data', (err, stdout) => {
      console.log(stdout);
    });
  }
}

module.exports = APIHandler;`,
      expectedTools: ['Read', 'Edit', 'MultiEdit'],
      description: 'Multiple vulnerability types in one file'
    }
  ];
  
  private testDir: string;
  private results: Map<string, ToolUsageStats[]> = new Map();
  
  constructor() {
    this.testDir = path.join(__dirname, 'claude-tool-monitoring-test');
  }
  
  async setup(): Promise<void> {
    console.log('🔧 Setting up tool monitoring test environment...\n');
    
    // Cleanup and create test directory
    try {
      await fs.rm(this.testDir, { recursive: true, force: true });
    } catch {}
    await fs.mkdir(this.testDir, { recursive: true });
    
    // Initialize git repo
    execSync('git init', { cwd: this.testDir });
    execSync('git config user.name "Tool Monitor"', { cwd: this.testDir });
    execSync('git config user.email "monitor@rsolv.ai"', { cwd: this.testDir });
  }
  
  async runScenario(scenario: TestScenario): Promise<ToolUsageStats[]> {
    console.log(`\n📊 Testing: ${scenario.name}`);
    console.log(`Description: ${scenario.description}`);
    console.log(`File: ${scenario.vulnerableFile}`);
    console.log('---');
    
    // Create vulnerable file
    const filePath = path.join(this.testDir, scenario.vulnerableFile);
    await fs.writeFile(filePath, scenario.vulnerableCode);
    
    // Commit it
    execSync(`git add ${scenario.vulnerableFile}`, { cwd: this.testDir });
    execSync(`git commit -m "Add ${scenario.vulnerableFile}"`, { cwd: this.testDir });
    
    // Track tool usage
    const toolUsage: Map<string, { count: number; files: Set<string> }> = new Map();
    let totalTools = 0;
    
    // Prepare prompt
    const prompt = `Fix all security vulnerabilities in ${scenario.vulnerableFile}.

IMPORTANT: You must use Edit or MultiEdit tools to modify the existing file. Do not create new files.

For SQL injection: Use parameterized queries
For XSS: Add proper escaping/sanitization
For Path traversal: Validate paths
For Command injection: Use safe execution methods

Make minimal changes to fix the issues while preserving functionality.`;
    
    console.log('\nRunning Claude Code...');
    
    try {
      // Run Claude Code with monitoring
      for await (const message of query({
        prompt,
        options: {
          cwd: this.testDir,
          maxTurns: 15,
          allowedTools: ['Read', 'Write', 'Edit', 'MultiEdit', 'Grep', 'Bash'],
          appendSystemPrompt: 'You are an expert at fixing security vulnerabilities. Always prefer editing existing files over creating new ones.'
        }
      })) {
        // Monitor tool usage - fixed for Claude Code SDK message structure
        if (message.type === 'assistant' && (message as any).message) {
          const assistantMsg = (message as any).message;
          if (assistantMsg.content && Array.isArray(assistantMsg.content)) {
            for (const block of assistantMsg.content) {
              if (block.type === 'tool_use' && block.name) {
                totalTools++;
                const toolName = block.name;
                
                if (!toolUsage.has(toolName)) {
                  toolUsage.set(toolName, { count: 0, files: new Set() });
                }
                
                const usage = toolUsage.get(toolName)!;
                usage.count++;
                
                // Track which files were touched
                if (block.input?.file_path || block.input?.path) {
                  const file = block.input.file_path || block.input.path;
                  usage.files.add(file);
                }
                
                // Log tool use
                console.log(`  🔧 ${toolName}${block.input?.file_path ? ` on ${path.basename(block.input.file_path)}` : ''}`);
              }
            }
          }
        }
      }
      
      // Calculate statistics
      const stats: ToolUsageStats[] = [];
      for (const [tool, usage] of toolUsage.entries()) {
        stats.push({
          toolName: tool,
          count: usage.count,
          percentage: (usage.count / totalTools) * 100,
          files: Array.from(usage.files)
        });
      }
      
      // Sort by usage
      stats.sort((a, b) => b.count - a.count);
      
      // Display results
      console.log('\n📈 Tool Usage Summary:');
      console.log(`Total tool calls: ${totalTools}`);
      stats.forEach(stat => {
        console.log(`  ${stat.toolName}: ${stat.count} (${stat.percentage.toFixed(1)}%)`);
        if (stat.files.length > 0) {
          console.log(`    Files: ${stat.files.join(', ')}`);
        }
      });
      
      // Check if the file was actually fixed
      const wasFixed = await this.validateFix(scenario.name, scenario.vulnerableFile);
      console.log(`\n✅ Fix validation: ${wasFixed ? 'PASS' : 'FAIL'}`);
      
      return stats;
      
    } catch (error) {
      console.error('❌ Scenario failed:', error.message);
      return [];
    }
  }
  
  async validateFix(scenarioName: string, vulnerableFile: string): Promise<boolean> {
    try {
      // Read the potentially fixed file
      const fixedContent = await fs.readFile(path.join(this.testDir, vulnerableFile), 'utf8');
      
      // Check if file was modified
      const gitStatus = execSync('git status --porcelain', { cwd: this.testDir, encoding: 'utf8' });
      if (!gitStatus.includes(vulnerableFile)) {
        console.log('  ⚠️  File was not modified');
        return false;
      }
      
      const fixIndicators = {
        'SQL Injection': ['?', 'parameterized', '$1', '[userId]', '[productId]', 'prepared statement'],
        'XSS': ['escape', 'sanitize', 'encode', 'textContent', 'DOMPurify', 'he.encode', 'innerText'],
        'Mixed': ['?', 'path.resolve', 'spawn', 'escape', 'execFile']
      };
      
      for (const [type, indicators] of Object.entries(fixIndicators)) {
        if (scenarioName.includes(type)) {
          const hasIndicator = indicators.some(indicator => fixedContent.includes(indicator));
          if (hasIndicator) {
            console.log(`  ✓ Found fix indicator for ${type}`);
          }
          return hasIndicator;
        }
      }
      
      return true; // Default to pass if no specific validation
    } catch (error) {
      console.log('  ❌ Error validating fix:', error.message);
      return false;
    }
  }
  
  async runAllScenarios(): Promise<void> {
    for (const scenario of this.scenarios) {
      const stats = await this.runScenario(scenario);
      this.results.set(scenario.name, stats);
      
      // Reset for next scenario
      execSync('git reset --hard', { cwd: this.testDir });
      execSync('git clean -fd', { cwd: this.testDir });
    }
  }
  
  generateReport(): void {
    console.log('\n\n📊 TOOL USAGE ANALYSIS REPORT');
    console.log('=====================================\n');
    
    // Aggregate statistics across all scenarios
    const aggregateTools: Map<string, { count: number; scenarios: string[] }> = new Map();
    let totalCalls = 0;
    
    for (const [scenario, stats] of this.results.entries()) {
      for (const stat of stats) {
        if (!aggregateTools.has(stat.toolName)) {
          aggregateTools.set(stat.toolName, { count: 0, scenarios: [] });
        }
        
        const agg = aggregateTools.get(stat.toolName)!;
        agg.count += stat.count;
        agg.scenarios.push(scenario);
        totalCalls += stat.count;
      }
    }
    
    // Calculate aggregate percentages
    const aggregateStats = Array.from(aggregateTools.entries())
      .map(([tool, data]) => ({
        tool,
        count: data.count,
        percentage: (data.count / totalCalls) * 100,
        scenarios: data.scenarios.length
      }))
      .sort((a, b) => b.count - a.count);
    
    console.log('📈 Aggregate Tool Usage:');
    console.log(`Total tool calls across all scenarios: ${totalCalls}`);
    aggregateStats.forEach(stat => {
      console.log(`  ${stat.tool}: ${stat.count} calls (${stat.percentage.toFixed(1)}%) - used in ${stat.scenarios}/${this.scenarios.length} scenarios`);
    });
    
    // Calculate Edit/MultiEdit vs Write ratio
    const editTools = aggregateStats
      .filter(s => s.tool === 'Edit' || s.tool === 'MultiEdit')
      .reduce((sum, s) => sum + s.count, 0);
    const writeTools = aggregateStats
      .filter(s => s.tool === 'Write')
      .reduce((sum, s) => sum + s.count, 0);
    
    const editRatio = totalCalls > 0 ? (editTools / totalCalls) * 100 : 0;
    
    console.log('\n🎯 Key Metrics:');
    console.log(`Edit/MultiEdit tool usage: ${editTools} calls (${editRatio.toFixed(1)}%)`);
    console.log(`Write tool usage: ${writeTools} calls`);
    console.log(`In-place editing ratio: ${editRatio.toFixed(1)}%`);
    
    // Success criteria
    const success = editRatio >= 80 && writeTools === 0;
    console.log(`\n${success ? '✅' : '❌'} Success Criteria: ${success ? 'PASS' : 'FAIL'}`);
    console.log(`  - Edit/MultiEdit >= 80%: ${editRatio >= 80 ? '✅' : '❌'} (${editRatio.toFixed(1)}%)`);
    console.log(`  - No Write tool usage: ${writeTools === 0 ? '✅' : '❌'} (${writeTools} calls)`);
    
    // Per-scenario breakdown
    console.log('\n📋 Per-Scenario Details:');
    for (const [scenario, stats] of this.results.entries()) {
      console.log(`\n${scenario}:`);
      stats.forEach(stat => {
        console.log(`  ${stat.toolName}: ${stat.count} (${stat.percentage.toFixed(1)}%)`);
      });
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
  // API key should be set via environment variable
  // export ANTHROPIC_API_KEY=your-api-key
  
  if (!process.env.ANTHROPIC_API_KEY) {
    console.error('❌ Error: ANTHROPIC_API_KEY environment variable not set');
    console.error('\nThis test requires real Claude Code API access to monitor actual tool usage.');
    console.error('Please set: export ANTHROPIC_API_KEY=your-api-key');
    
    // Create a simulated result for documentation
    console.log('\n📝 Creating simulated results for documentation...');
    
    const simulatedResults = {
      timestamp: new Date().toISOString(),
      aggregateToolUsage: {
        Read: { count: 9, percentage: 25.7 },
        Edit: { count: 18, percentage: 51.4 },
        MultiEdit: { count: 6, percentage: 17.1 },
        Write: { count: 0, percentage: 0 },
        Grep: { count: 2, percentage: 5.7 }
      },
      editRatio: 68.5,
      writeRatio: 0,
      success: false,
      note: 'Simulated results - real API key required for actual testing'
    };
    
    await fs.writeFile(
      'tool-monitoring-simulated-results.json',
      JSON.stringify(simulatedResults, null, 2)
    );
    
    console.log('Simulated results saved to tool-monitoring-simulated-results.json');
    return;
  }
  
  console.log('🚀 Claude Code Tool Usage Monitoring Test');
  console.log('========================================\n');
  
  const monitor = new ToolUsageMonitor();
  
  try {
    await monitor.setup();
    await monitor.runAllScenarios();
    monitor.generateReport();
    
    // Save results
    const aggregateTools: Map<string, { count: number; scenarios: string[] }> = new Map();
    let totalCalls = 0;
    
    for (const [scenario, stats] of monitor['results'].entries()) {
      for (const stat of stats) {
        if (!aggregateTools.has(stat.toolName)) {
          aggregateTools.set(stat.toolName, { count: 0, scenarios: [] });
        }
        
        const agg = aggregateTools.get(stat.toolName)!;
        agg.count += stat.count;
        agg.scenarios.push(scenario);
        totalCalls += stat.count;
      }
    }
    
    const editTools = Array.from(aggregateTools.entries())
      .filter(([tool]) => tool === 'Edit' || tool === 'MultiEdit')
      .reduce((sum, [, data]) => sum + data.count, 0);
    const writeTools = Array.from(aggregateTools.entries())
      .filter(([tool]) => tool === 'Write')
      .reduce((sum, [, data]) => sum + data.count, 0);
    
    const results = {
      timestamp: new Date().toISOString(),
      scenarios: Object.fromEntries(monitor['results']),
      aggregateStats: Object.fromEntries(
        Array.from(aggregateTools.entries()).map(([tool, data]) => [
          tool, 
          { count: data.count, percentage: (data.count / totalCalls) * 100 }
        ])
      ),
      keyMetrics: {
        totalToolCalls: totalCalls,
        editMultiEditCalls: editTools,
        writeCalls: writeTools,
        inPlaceEditingRatio: totalCalls > 0 ? (editTools / totalCalls) * 100 : 0,
        success: editTools >= (totalCalls * 0.8) && writeTools === 0
      },
      summary: 'Claude Code tool usage monitoring completed successfully'
    };
    
    await fs.writeFile(
      'tool-monitoring-results.json',
      JSON.stringify(results, null, 2)
    );
    
  } catch (error) {
    console.error('Test failed:', error);
    process.exit(1);
  } finally {
    await monitor.cleanup();
  }
}

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}