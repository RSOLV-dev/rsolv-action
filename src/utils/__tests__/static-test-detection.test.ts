/**
 * Test suite for static test detection (RFC-103 Phase 3)
 *
 * Tests the isStaticTest() function which detects whether generated test code
 * is a static source analysis test (reads file + regex) versus a behavioral
 * test (imports module, calls functions, mocks side effects).
 */

import { describe, it, expect } from 'vitest';
import { isStaticTest } from '../test-result-classifier.js';

describe('isStaticTest (RFC-103 Phase 3)', () => {
  describe('JavaScript static patterns', () => {
    it('should detect fs.readFileSync + includes as static', () => {
      const code = `
const fs = require('fs');
const source = fs.readFileSync('app/handler.js', 'utf8');
assert(source.includes('eval('));
`;
      const result = isStaticTest(code);
      expect(result.isStatic).toBe(true);
      expect(result.reason).toContain('fs.readFileSync');
    });

    it('should detect fs.readFileSync + regex.test as static', () => {
      const code = `
const fs = require('fs');
const source = fs.readFileSync('routes/users.js', 'utf8');
expect(/eval\\s*\\(/.test(source)).toBe(true);
`;
      const result = isStaticTest(code);
      expect(result.isStatic).toBe(true);
    });

    it('should detect fs.readFileSync + match as static', () => {
      const code = `
import { readFileSync } from 'fs';
const content = readFileSync('index.js', 'utf8');
const matches = content.match(/exec\\(/g);
expect(matches.length).toBeGreaterThan(0);
`;
      const result = isStaticTest(code);
      expect(result.isStatic).toBe(true);
    });

    it('should detect fs.readFileSync + new RegExp as static', () => {
      const code = `
const fs = require('fs');
const src = fs.readFileSync('app.js', 'utf8');
const pattern = new RegExp('eval\\\\(');
expect(pattern.test(src)).toBe(true);
`;
      const result = isStaticTest(code);
      expect(result.isStatic).toBe(true);
    });
  });

  describe('PHP static patterns', () => {
    it('should detect file_get_contents + preg_match as static', () => {
      const code = `
$source = file_get_contents('src/Controller.php');
$this->assertMatchesRegularExpression('/md5\\(/', $source);
`;
      const result = isStaticTest(code);
      expect(result.isStatic).toBe(true);
      expect(result.reason).toContain('file_get_contents');
    });

    it('should detect file_get_contents + assertStringContains as static', () => {
      const code = `
$content = file_get_contents('UserController.php');
$this->assertStringContainsString('eval(', $content);
`;
      const result = isStaticTest(code);
      expect(result.isStatic).toBe(true);
    });
  });

  describe('Python static patterns', () => {
    it('should detect open() + re.search as static', () => {
      const code = `
import re
with open('app/views.py', 'r') as f:
    source = f.read()
assert re.search(r'eval\\(', source)
`;
      const result = isStaticTest(code);
      expect(result.isStatic).toBe(true);
      expect(result.reason).toContain('file read');
    });

    it('should detect Path.read_text + re.findall as static', () => {
      const code = `
from pathlib import Path
import re
content = Path('app.py').read_text()
matches = re.findall(r'exec\\(', content)
assert len(matches) > 0
`;
      const result = isStaticTest(code);
      expect(result.isStatic).toBe(true);
    });

    it('should detect open + "in source" as static', () => {
      const code = `
with open('handler.py') as f:
    source = f.read()
assert 'eval(' in source
`;
      const result = isStaticTest(code);
      expect(result.isStatic).toBe(true);
    });
  });

  describe('Ruby static patterns', () => {
    it('should detect File.read + match as static', () => {
      const code = `
source = File.read('app/models/user.rb')
expect(source).to match(/Marshal\\.load/)
`;
      const result = isStaticTest(code);
      expect(result.isStatic).toBe(true);
      expect(result.reason).toContain('File.read');
    });

    it('should detect File.read + include? as static', () => {
      const code = `
content = File.read('config/routes.rb')
expect(content.include?('eval')).to be true
`;
      const result = isStaticTest(code);
      expect(result.isStatic).toBe(true);
    });
  });

  describe('Elixir static patterns', () => {
    it('should detect File.read! + Regex.match? as static', () => {
      const code = `
source = File.read!("lib/app_web/controllers/user_controller.ex")
assert Regex.match?(~r/IO\\.inspect/, source)
`;
      const result = isStaticTest(code);
      expect(result.isStatic).toBe(true);
      expect(result.reason).toContain('File.read!');
    });

    it('should detect File.read! + String.contains? as static', () => {
      const code = `
content = File.read!("lib/app.ex")
assert String.contains?(content, "eval")
`;
      const result = isStaticTest(code);
      expect(result.isStatic).toBe(true);
    });
  });

  describe('explicit fallback comment', () => {
    it('should detect "source analysis fallback" comment as static', () => {
      const code = `
// Source analysis fallback — could not import module
const fs = require('fs');
const src = fs.readFileSync('app.js', 'utf8');
`;
      const result = isStaticTest(code);
      expect(result.isStatic).toBe(true);
      expect(result.reason).toContain('Source analysis fallback');
    });
  });

  describe('behavioral tests (should NOT be static)', () => {
    it('should classify require + function call as behavioral', () => {
      const code = `
const { search } = require('../core/appHandler');
const sinon = require('sinon');
const dbStub = sinon.stub(db, 'query');
search({ query: "' OR '1'='1" });
expect(dbStub.firstCall.args[0]).to.include("' OR '1'='1");
`;
      const result = isStaticTest(code);
      expect(result.isStatic).toBe(false);
      expect(result.reason).toContain('behavioral');
    });

    it('should classify import + mock as behavioral', () => {
      const code = `
import { describe, it, expect, vi } from 'vitest';
import * as cp from 'child_process';
vi.mock('child_process');
const { ping } = await import('../core/appHandler.js');
ping({ body: { address: '127.0.0.1; cat /etc/passwd' } }, { render: vi.fn() });
expect(cp.exec).toHaveBeenCalledWith(expect.stringContaining('; cat /etc/passwd'));
`;
      const result = isStaticTest(code);
      expect(result.isStatic).toBe(false);
    });

    it('should classify Python unittest.mock.patch as behavioral', () => {
      const code = `
from unittest.mock import patch
import app.views as views

with patch('builtins.eval') as mock_eval:
    views.handle_input("__import__('os').system('ls')")
    mock_eval.assert_called_once()
`;
      const result = isStaticTest(code);
      expect(result.isStatic).toBe(false);
    });

    it('should classify RSpec allow/receive as behavioral', () => {
      const code = `
describe User do
  it 'allows Marshal.load with untrusted input' do
    allow(Marshal).to receive(:load).and_call_original
    expect { User.deserialize(malicious_payload) }.not_to raise_error
  end
end
`;
      const result = isStaticTest(code);
      expect(result.isStatic).toBe(false);
    });

    it('should classify ExUnit test with Application.get_env as behavioral', () => {
      const code = `
defmodule AppWeb.SecurityTest do
  use ExUnit.Case
  test "debug mode exposes sensitive info" do
    config = Application.get_env(:app, AppWeb.Endpoint)
    assert config[:debug_errors] == true
  end
end
`;
      const result = isStaticTest(code);
      expect(result.isStatic).toBe(false);
    });

    it('should return not static for empty or null input', () => {
      expect(isStaticTest('').isStatic).toBe(false);
      expect(isStaticTest(null as unknown as string).isStatic).toBe(false);
    });
  });
});
