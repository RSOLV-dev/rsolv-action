#!/usr/bin/env bun

/**
 * Demonstration of Universal Framework Detection with Claude Code SDK
 * 
 * Shows how we could replace all language-specific detection logic
 * with a single AI-powered detector.
 */

import { ClaudeFrameworkDetector } from '../src/ai/claude-framework-detector.js';
import { TestFrameworkDetector } from '../src/ai/test-framework-detector.js';
import { logger } from '../src/utils/logger.js';
import * as path from 'path';
import * as fs from 'fs';

async function compareDetectionMethods() {
  const projects = [
    { name: 'nodegoat', path: path.join(process.cwd(), 'nodegoat'), language: 'javascript' },
    { name: 'railsgoat', path: path.join(process.cwd(), 'vulnerable-apps/railsgoat'), language: 'ruby' },
    { name: 'pygoat', path: path.join(process.cwd(), 'vulnerable-apps/pygoat'), language: 'python' },
    { name: 'django-vulnerable', path: path.join(process.cwd(), 'vulnerable-apps/django-vulnerable'), language: 'python' }
  ];
  
  logger.info('Comparing Traditional vs Claude Code SDK Detection');
  logger.info('='.repeat(60));
  
  for (const project of projects) {
    if (!fs.existsSync(project.path)) {
      logger.warn(`Skipping ${project.name} - not found`);
      continue;
    }
    
    logger.info(`\n${project.name} (${project.language}):`);
    logger.info('-'.repeat(40));
    
    // Traditional detection
    const traditionalDetector = new TestFrameworkDetector();
    const traditionalResult = await traditionalDetector.detectFrameworks(project.path);
    
    logger.info('Traditional Detection:');
    if (traditionalResult.detected && traditionalResult.primaryFramework) {
      logger.info(`  Framework: ${traditionalResult.primaryFramework.name}`);
      logger.info(`  Version: ${traditionalResult.primaryFramework.version}`);
      logger.info(`  Confidence: ${traditionalResult.primaryFramework.confidence}`);
    } else {
      logger.info('  Not detected');
    }
    
    // Claude SDK detection (mock)
    const claudeDetector = new ClaudeFrameworkDetector();
    const claudeResult = await claudeDetector.detectFrameworks(project.path);
    
    logger.info('\nClaude SDK Detection (Mock):');
    if (claudeResult.detected && claudeResult.primaryFramework) {
      logger.info(`  Framework: ${claudeResult.primaryFramework.name}`);
      logger.info(`  Version: ${claudeResult.primaryFramework.version}`);
      logger.info(`  Confidence: ${claudeResult.primaryFramework.confidence}`);
      logger.info(`  Test Command: ${claudeResult.suggestedTestCommand}`);
      if (claudeResult.reasoning) {
        logger.info(`  Reasoning: ${claudeResult.reasoning}`);
      }
    } else {
      logger.info('  Not detected');
    }
  }
  
  logger.info('\n\nAdvantages of Claude SDK Approach:');
  logger.info('='.repeat(60));
  
  const advantages = [
    {
      title: 'Universal Language Support',
      description: 'Works with any programming language without hardcoded patterns'
    },
    {
      title: 'Context Understanding',
      description: 'Can infer from README, CI configs, and other documentation'
    },
    {
      title: 'Handles Edge Cases',
      description: 'Understands custom setups, monorepos, and unconventional structures'
    },
    {
      title: 'Test Command Generation',
      description: 'Can suggest the exact command to run tests, even complex ones'
    },
    {
      title: 'Setup Instructions',
      description: 'Provides step-by-step setup if dependencies need installation'
    },
    {
      title: 'Framework Variants',
      description: 'Understands framework plugins and extensions (e.g., pytest-django)'
    },
    {
      title: 'Fallback Intelligence',
      description: 'Can make educated guesses even with minimal information'
    },
    {
      title: 'Single Implementation',
      description: 'One detector for all languages vs. maintaining patterns for each'
    }
  ];
  
  advantages.forEach(({ title, description }) => {
    logger.info(`\n${title}:`);
    logger.info(`  ${description}`);
  });
  
  logger.info('\n\nImplementation Strategy:');
  logger.info('='.repeat(60));
  logger.info(`
1. Start with traditional detection for speed and offline use
2. Fall back to Claude SDK for unknown or complex cases
3. Cache Claude SDK results to avoid repeated API calls
4. Use Claude SDK to improve traditional patterns over time

Example hybrid approach:

async function detectTestFramework(repoPath: string) {
  // Try traditional detection first (fast, offline)
  const traditional = await traditionalDetector.detect(repoPath);
  
  if (traditional.confidence > 0.8) {
    return traditional;
  }
  
  // Fall back to Claude SDK for complex cases
  const claude = await claudeDetector.detect(repoPath);
  
  // Cache the result
  await cacheResult(repoPath, claude);
  
  // Learn from Claude's detection to improve patterns
  if (claude.detected) {
    await updatePatterns(claude.reasoning, traditional);
  }
  
  return claude;
}
`);
  
  logger.info('\nEstimated API Costs:');
  logger.info('- ~500-1000 tokens per detection');
  logger.info('- ~$0.003 per detection with Claude 3 Sonnet');
  logger.info('- Cache results to minimize repeated calls');
  logger.info('- Use only for repositories where traditional detection fails');
}

// Run the comparison
compareDetectionMethods().catch(console.error);