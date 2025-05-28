#!/usr/bin/env node
/**
 * Unified demo runner for RSOLV action
 * 
 * Usage:
 *   bun run demo                    # Run basic demo
 *   bun run demo environment        # Run environment demo
 *   bun run demo context           # Run context evaluation
 *   bun run demo security          # Run security analysis demo
 */

import { Command } from 'commander';
import { runBasicDemo } from './basic.js';
import { runEnvironmentDemo } from './environment.js';
import { runContextEvaluation } from './context.js';
import { runSecurityDemo } from './security.js';

const program = new Command();

program
  .name('rsolv-demo')
  .description('RSOLV action demonstration tool')
  .version('1.0.0');

program
  .command('basic', { isDefault: true })
  .description('Run basic demo showing core functionality')
  .action(async () => {
    await runBasicDemo();
  });

program
  .command('environment')
  .description('Run interactive environment demo')
  .action(async () => {
    await runEnvironmentDemo();
  });

program
  .command('context')
  .description('Run context evaluation demo')
  .action(async () => {
    await runContextEvaluation();
  });

program
  .command('security')
  .description('Run security analysis demo')
  .action(async () => {
    await runSecurityDemo();
  });

// Parse command line arguments
program.parse();