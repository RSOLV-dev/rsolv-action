import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { LocalFileSource } from '../local-file-source.js';

describe('LocalFileSource', () => {
  let root: string;
  let outside: string;

  const write = (relative: string, content: string | Buffer): void => {
    fs.mkdirSync(path.dirname(path.join(root, relative)), { recursive: true });
    fs.writeFileSync(path.join(root, relative), content);
  };

  beforeEach(() => {
    const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'rsolv-local-source-')));
    root = path.join(base, 'work');
    outside = path.join(base, 'outside');
    fs.mkdirSync(root);
    fs.mkdirSync(outside);
  });

  afterEach(() => {
    fs.rmSync(path.dirname(root), { recursive: true, force: true });
  });

  describe('list', () => {
    it('lists code files under the root with their language, relative to it', async () => {
      write('app.js', 'eval(x)');
      write('lib/db.py', 'import os');
      write('README.md', '# hi');
      write('assets/logo.png', Buffer.from([0x89, 0x50]));

      const files = await new LocalFileSource(root).list();

      expect(files.sort((a, b) => a.path.localeCompare(b.path))).toEqual([
        { path: 'app.js', content: 'eval(x)', language: 'javascript' },
        { path: 'lib/db.py', content: 'import os', language: 'python' },
      ]);
    });

    it('keeps the files the scanner filters later, as the GitHub listing does', async () => {
      write('test/app.test.js', 'x');
      write('vendor/jquery.min.js', 'y');

      const paths = (await new LocalFileSource(root).list()).map((f) => f.path).sort();

      expect(paths).toEqual(['test/app.test.js', 'vendor/jquery.min.js']);
    });

    it('skips .git', async () => {
      write('.git/hooks/pre-commit.js', 'x');

      await expect(new LocalFileSource(root).list()).resolves.toEqual([]);
    });

    it('skips files of 1,000,000 bytes or more', async () => {
      write('big.js', 'a'.repeat(1_000_000));
      write('small.js', 'a'.repeat(999_999));

      const paths = (await new LocalFileSource(root).list()).map((f) => f.path);

      expect(paths).toEqual(['small.js']);
    });

    it('does not follow symlinks, to files or directories, out of the root', async () => {
      fs.writeFileSync(path.join(outside, 'secret.js'), 'secret');
      fs.symlinkSync(path.join(outside, 'secret.js'), path.join(root, 'link.js'));
      fs.symlinkSync(outside, path.join(root, 'linkdir'));

      await expect(new LocalFileSource(root).list()).resolves.toEqual([]);
    });
  });

  describe('read', () => {
    it('reads a file under the root', async () => {
      write('config/database.yml', 'adapter: postgresql');

      await expect(new LocalFileSource(root).read('config/database.yml')).resolves.toBe('adapter: postgresql');
    });

    it('answers null for a missing file', async () => {
      await expect(new LocalFileSource(root).read('Gemfile')).resolves.toBeNull();
    });

    it('answers null for a symlink, or a path through one, that leaves the root', async () => {
      fs.writeFileSync(path.join(outside, 'Gemfile'), 'outside');
      fs.mkdirSync(path.join(outside, 'config'));
      fs.writeFileSync(path.join(outside, 'config', 'database.yml'), 'outside');
      fs.symlinkSync(path.join(outside, 'Gemfile'), path.join(root, 'Gemfile'));
      fs.symlinkSync(path.join(outside, 'config'), path.join(root, 'config'));

      const source = new LocalFileSource(root);

      await expect(source.read('Gemfile')).resolves.toBeNull();
      await expect(source.read('config/database.yml')).resolves.toBeNull();
      await expect(source.read('../outside/Gemfile')).resolves.toBeNull();
    });
  });
});
