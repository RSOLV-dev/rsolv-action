import { describe, it, expect, vi, beforeEach } from 'vitest';
import { GitCliScanner } from '../git-cli-scanner.js';
import * as fs from 'fs';
import * as childProcess from 'child_process';

vi.mock('fs');
vi.mock('child_process');

const mockExecSync = vi.mocked(childProcess.execSync);
const mockReadFileSync = vi.mocked(fs.readFileSync);
const mockExistsSync = vi.mocked(fs.existsSync);

describe('GitCliScanner', () => {
  let scanner: GitCliScanner;

  beforeEach(() => {
    vi.clearAllMocks();
    scanner = new GitCliScanner('/workspace/repo');
  });

  describe('getFileTree', () => {
    it('lists files from local git repo', () => {
      mockExecSync.mockReturnValue(Buffer.from(
        'src/app.py\nsrc/db/queries.py\ntests/test_app.py\nrequirements.txt\n'
      ));

      const result = scanner.getFileTree();

      expect(mockExecSync).toHaveBeenCalledWith(
        'git ls-tree -r --name-only HEAD',
        { cwd: '/workspace/repo', maxBuffer: 10 * 1024 * 1024 }
      );

      expect(result).toHaveLength(4);
      expect(result[0]).toEqual({
        path: 'src/app.py',
        type: 'blob',
        sha: '',
      });
    });

    it('filters empty lines', () => {
      mockExecSync.mockReturnValue(Buffer.from(
        'src/app.py\n\nsrc/db.py\n\n'
      ));

      const result = scanner.getFileTree();
      expect(result).toHaveLength(2);
    });
  });

  describe('getFileContent', () => {
    it('reads from local filesystem', () => {
      mockReadFileSync.mockReturnValue('print("hello")');

      const result = scanner.getFileContent('src/app.py');

      expect(mockReadFileSync).toHaveBeenCalledWith(
        '/workspace/repo/src/app.py',
        'utf-8'
      );
      expect(result).toBe('print("hello")');
    });

    it('returns null for missing files', () => {
      mockReadFileSync.mockImplementation(() => {
        throw new Error('ENOENT: no such file or directory');
      });

      const result = scanner.getFileContent('missing.py');
      expect(result).toBeNull();
    });
  });

  describe('getManifestFiles', () => {
    it('reads all MANIFEST_FILES that exist', () => {
      mockExistsSync.mockImplementation((path) => {
        const p = path as string;
        return p.endsWith('requirements.txt') || p.endsWith('pyproject.toml');
      });

      mockReadFileSync.mockImplementation((path) => {
        const p = path as string;
        if (p.endsWith('requirements.txt')) return 'flask==2.3.0\n';
        if (p.endsWith('pyproject.toml')) return '[tool.pytest]\n';
        throw new Error('ENOENT');
      });

      const result = scanner.getManifestFiles();

      expect(result['requirements.txt']).toBe('flask==2.3.0\n');
      expect(result['pyproject.toml']).toBe('[tool.pytest]\n');
      // Should not include files that don't exist
      expect(result['Gemfile']).toBeUndefined();
    });

    it('handles missing repo path gracefully', () => {
      mockExistsSync.mockReturnValue(false);

      const result = scanner.getManifestFiles();
      expect(Object.keys(result)).toHaveLength(0);
    });
  });
});
