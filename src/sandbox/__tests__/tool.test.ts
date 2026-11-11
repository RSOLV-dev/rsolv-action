import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runTool } from '../tool.js';

describe('runTool', () => {
  let tmpDir: string;
  let previousCwd: string;

  beforeEach(() => {
    previousCwd = process.cwd();
    tmpDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'rsolv-sandbox-tool-')));
    process.chdir(tmpDir);
    fs.writeFileSync('app.js', 'const secret = "x";\n');
  });

  afterEach(() => {
    process.chdir(previousCwd);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('read_file returns {content}', async () => {
    await expect(runTool({ tool: 'read_file', input: { path: 'app.js' } }))
      .resolves.toEqual({ content: 'const secret = "x";\n' });
  });

  it('write_file returns {success} and writes relative to the working directory', async () => {
    await expect(runTool({ tool: 'write_file', input: { path: 'new/b.js', content: 'b' } }))
      .resolves.toEqual({ success: true });
    expect(fs.readFileSync(path.join(tmpDir, 'new/b.js'), 'utf-8')).toBe('b');
  });

  it('edit_file returns {success}', async () => {
    await expect(runTool({ tool: 'edit_file', input: { path: 'app.js', old_string: 'secret', new_string: 'value' } }))
      .resolves.toEqual({ success: true });
  });

  it('glob returns {files}', async () => {
    await expect(runTool({ tool: 'glob', input: { pattern: '*.js' } }))
      .resolves.toEqual({ files: ['app.js'] });
  });

  it('grep returns {matches}', async () => {
    await expect(runTool({ tool: 'grep', input: { pattern: 'secret', path: '.' } }))
      .resolves.toEqual({ matches: [{ file: './app.js', line_number: 1, line: 'const secret = "x";' }] });
  });

  it('bash returns {stdout, stderr, exit_code}', async () => {
    await expect(runTool({ tool: 'bash', input: { command: 'echo hi; echo oops >&2; exit 3' } }))
      .resolves.toEqual({ stdout: 'hi\n', stderr: 'oops\n', exit_code: 3 });
  });

  it('answers an unknown tool with {error: "unknown tool"}', async () => {
    await expect(runTool({ tool: 'rm_rf', input: {} })).resolves.toEqual({ error: 'unknown tool' });
  });

  it('does not treat inherited object properties as tools', async () => {
    await expect(runTool({ tool: 'constructor', input: {} })).resolves.toEqual({ error: 'unknown tool' });
  });

  it('answers a request without an input object with an error', async () => {
    await expect(runTool({ tool: 'read_file' })).resolves.toEqual({ error: 'malformed tool request' });
  });
});
