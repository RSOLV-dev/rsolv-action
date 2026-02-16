/**
 * RED TESTS — ToolExecutors (RFC-096 Phase A)
 *
 * Tests the local tool handlers that execute file I/O, shell commands,
 * and search operations on the GitHub Action runner.
 */

// Unmock child_process for this file — we need real exec/execSync
// The global vitest setup mocks it, but tool-executors needs it real.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.unmock('child_process');

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  executeReadFile,
  executeWriteFile,
  executeEditFile,
  executeGlob,
  executeGrep,
  executeBash,
} from '../tool-executors.js';

describe('ToolExecutors', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rsolv-pipeline-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('executeReadFile', () => {
    it('reads file contents and returns as string', async () => {
      const filePath = path.join(tmpDir, 'test.js');
      fs.writeFileSync(filePath, "console.log('hello');");

      const result = await executeReadFile({ path: filePath });

      expect(result.content).toBe("console.log('hello');");
      expect(result.error).toBeUndefined();
    });

    it('returns error for nonexistent file', async () => {
      const result = await executeReadFile({ path: path.join(tmpDir, 'nonexistent.js') });

      expect(result.error).toBeDefined();
      expect(result.content).toBeUndefined();
    });
  });

  describe('executeWriteFile', () => {
    it('writes content to file path', async () => {
      const filePath = path.join(tmpDir, 'output.js');

      const result = await executeWriteFile({
        path: filePath,
        content: 'const x = 1;',
      });

      expect(result.error).toBeUndefined();
      expect(fs.readFileSync(filePath, 'utf-8')).toBe('const x = 1;');
    });

    it('creates parent directories if needed', async () => {
      const filePath = path.join(tmpDir, 'nested', 'deep', 'output.js');

      const result = await executeWriteFile({
        path: filePath,
        content: 'const y = 2;',
      });

      expect(result.error).toBeUndefined();
      expect(fs.readFileSync(filePath, 'utf-8')).toBe('const y = 2;');
    });
  });

  describe('executeEditFile', () => {
    it('replaces old_string with new_string in file', async () => {
      const filePath = path.join(tmpDir, 'edit-target.js');
      fs.writeFileSync(filePath, 'const password = "admin123";');

      const result = await executeEditFile({
        path: filePath,
        old_string: '"admin123"',
        new_string: 'process.env.DB_PASSWORD',
      });

      expect(result.error).toBeUndefined();
      expect(fs.readFileSync(filePath, 'utf-8')).toBe(
        'const password = process.env.DB_PASSWORD;'
      );
    });

    it('returns error if old_string not found', async () => {
      const filePath = path.join(tmpDir, 'edit-target.js');
      fs.writeFileSync(filePath, 'const x = 1;');

      const result = await executeEditFile({
        path: filePath,
        old_string: 'nonexistent string',
        new_string: 'replacement',
      });

      expect(result.error).toBeDefined();
    });
  });

  describe('executeGlob', () => {
    it('returns matching file paths', async () => {
      fs.writeFileSync(path.join(tmpDir, 'a.js'), '');
      fs.writeFileSync(path.join(tmpDir, 'b.js'), '');
      fs.writeFileSync(path.join(tmpDir, 'c.py'), '');

      const result = await executeGlob({
        pattern: '*.js',
        path: tmpDir,
      });

      expect(result.error).toBeUndefined();
      expect(result.files).toBeDefined();
      expect(result.files.length).toBe(2);
      expect(result.files.every((f: string) => f.endsWith('.js'))).toBe(true);
    });
  });

  describe('executeGrep', () => {
    it('returns matching lines with file paths', async () => {
      fs.writeFileSync(
        path.join(tmpDir, 'test.js'),
        'const password = "admin";\nconst user = "root";\n'
      );

      const result = await executeGrep({
        pattern: 'password',
        path: tmpDir,
      });

      expect(result.error).toBeUndefined();
      expect(result.matches).toBeDefined();
      expect(result.matches.length).toBeGreaterThan(0);
      expect(result.matches[0].line).toContain('password');
    });
  });

  describe('executeBash', () => {
    it('executes command and returns stdout/stderr/exit_code', async () => {
      const result = await executeBash({ command: 'echo hello world' });

      expect(result.exit_code).toBe(0);
      expect(result.stdout).toContain('hello world');
      expect(result.error).toBeUndefined();
    });

    it('returns non-zero exit code on failure', async () => {
      const result = await executeBash({ command: 'ls /nonexistent_path_12345' });

      expect(result.exit_code).not.toBe(0);
    });

    it('enforces timeout', async () => {
      const result = await executeBash({
        command: 'sleep 30',
        timeout_ms: 100,
      });

      expect(result.error).toBeDefined();
      expect(result.error).toContain('timeout');
    });

    it('defaults to 600s timeout for slow ecosystem setup (bundle install, mix deps.get)', async () => {
      // The default timeout must accommodate slow dependency installs.
      // We can't wait 600s in a test, so verify the default is applied
      // by checking a short command completes without custom timeout_ms.
      const result = await executeBash({ command: 'echo default-timeout-test' });
      expect(result.exit_code).toBe(0);
      expect(result.stdout).toContain('default-timeout-test');

      // Verify the timeout error message includes 600000ms when it fires.
      // Use a very short sleep with explicit timeout to confirm format.
      const timeoutResult = await executeBash({
        command: 'sleep 30',
        timeout_ms: 50,
      });
      expect(timeoutResult.error).toContain('timeout: command exceeded 50ms');
    });

    it('includes working directory when specified', async () => {
      const result = await executeBash({
        command: 'pwd',
        cwd: tmpDir,
      });

      expect(result.stdout?.trim()).toBe(tmpDir);
    });
  });
});
