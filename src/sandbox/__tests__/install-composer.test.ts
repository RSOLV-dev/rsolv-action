import { describe, it, expect } from 'vitest';
import { execFile } from 'child_process';
import { existsSync, mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';

const SCRIPT = resolve(__dirname, '../../../scripts/install-composer.sh');

function install(source: string, dest: string): Promise<{ code: number; stderr: string }> {
  return new Promise((done) => {
    execFile('sh', [SCRIPT, dest], { env: { ...process.env, COMPOSER_PHAR_URL: source } }, (error, _stdout, stderr) => {
      done({ code: error ? Number(error.code ?? 1) : 0, stderr: String(stderr) });
    });
  });
}

describe('install-composer.sh', () => {
  describe('when the downloaded phar is not the pinned one', () => {
    it('refuses it and installs nothing', async () => {
      const dir = mkdtempSync(join(tmpdir(), 'composer-'));
      const tampered = join(dir, 'composer.phar');
      writeFileSync(tampered, '#!/usr/bin/env php\n<?php echo "not composer";\n');
      const dest = join(dir, 'bin', 'composer');

      const { code, stderr } = await install(`file://${tampered}`, dest);

      expect(code).not.toBe(0);
      expect(stderr).toMatch(/SHA-256/);
      expect(existsSync(dest)).toBe(false);
    });
  });

  describe('when the download fails', () => {
    it('installs nothing', async () => {
      const dir = mkdtempSync(join(tmpdir(), 'composer-'));
      const dest = join(dir, 'composer');

      const { code } = await install(`file://${join(dir, 'missing.phar')}`, dest);

      expect(code).not.toBe(0);
      expect(existsSync(dest)).toBe(false);
    });
  });
});
