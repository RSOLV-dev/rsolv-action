/**
 * TestRunner Service
 * RFC-060 Phase 3.2: Test execution service for validation
 */

import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export interface TestRunResult {
  passed: boolean;
  output: string;
}

export class TestRunner {
  /**
   * Run a test command and return the result
   */
  async runTest(command: string): Promise<TestRunResult> {
    try {
      const { stdout, stderr } = await execAsync(command);

      // Check if tests passed (exit code 0)
      return {
        passed: true,
        output: stdout + stderr
      };
    } catch (error: any) {
      // Tests failed (non-zero exit code)
      return {
        passed: false,
        output: error.stdout + error.stderr
      };
    }
  }

  /**
   * Validate test framework is available
   */
  async validate(): Promise<boolean> {
    try {
      await execAsync('npm test --version');
      return true;
    } catch {
      return false;
    }
  }
}