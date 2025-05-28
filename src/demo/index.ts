/**
 * Unified Demo Module for RSOLV
 * Consolidates all demo functionality into a single entry point
 */

export interface DemoCommand {
  name: string;
  description: string;
  handler: () => Promise<void>;
}

// Import individual demo modules as they're converted
// For now, we'll define the structure for future implementation

export const demoCommands: Record<string, DemoCommand> = {
  'basic': {
    name: 'basic',
    description: 'Basic issue processing and PR creation demo',
    handler: async () => {
      // TODO: Import functionality from src/demo.ts
      console.log('Basic demo - to be implemented');
    }
  },
  'environment': {
    name: 'environment',
    description: 'Comprehensive demo environment with all components',
    handler: async () => {
      // TODO: Import functionality from demo-environment.ts
      console.log('Environment demo - to be implemented');
    }
  },
  'context': {
    name: 'context',
    description: 'Context quality evaluation demo',
    handler: async () => {
      // TODO: Import functionality from src/demo-context-evaluation.ts
      console.log('Context evaluation demo - to be implemented');
    }
  },
  'security': {
    name: 'security',
    description: 'Security analysis and vulnerability detection demo',
    handler: async () => {
      // TODO: Import functionality from src/security-demo.ts
      console.log('Security demo - to be implemented');
    }
  }
};

/**
 * Main demo runner
 */
export async function runDemo(command?: string): Promise<void> {
  if (!command || !demoCommands[command]) {
    console.log('Available demo commands:');
    Object.entries(demoCommands).forEach(([key, cmd]) => {
      console.log(`  ${key.padEnd(15)} - ${cmd.description}`);
    });
    return;
  }

  const demo = demoCommands[command];
  console.log(`Running ${demo.name} demo...`);
  await demo.handler();
}

// Export individual demo functions for direct use
export { runContextEvaluation } from '../demo-context-evaluation.js';
// TODO: Export other demo functions as they're modularized