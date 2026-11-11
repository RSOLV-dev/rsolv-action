import * as fs from 'fs/promises';
import * as path from 'path';
import { RepositoryScanner, type FileSource } from './repository-scanner.js';
import type { FileToScan } from './types.js';

const MAX_FILE_BYTES = 1_000_000;

/**
 * The scanner's files from a checkout on disk (the v5 sandbox's /work), with
 * the GitHub listing's filter: code files under 1,000,000 bytes. `.git` and
 * symlinks are skipped, so nothing outside the root is read.
 */
export class LocalFileSource implements FileSource {
  constructor(private readonly root: string) {}

  async list(): Promise<FileToScan[]> {
    const files: FileToScan[] = [];
    await this.walk('', files);
    return files;
  }

  async read(relative: string): Promise<string | null> {
    try {
      const root = await fs.realpath(this.root);
      const real = await fs.realpath(path.join(root, relative));
      if (!real.startsWith(root + path.sep)) return null;
      const stat = await fs.stat(real);
      return stat.isFile() && stat.size < MAX_FILE_BYTES ? await fs.readFile(real, 'utf-8') : null;
    } catch {
      return null;
    }
  }

  private async walk(dir: string, files: FileToScan[]): Promise<void> {
    for (const entry of await fs.readdir(path.join(this.root, dir), { withFileTypes: true })) {
      const relative = dir ? `${dir}/${entry.name}` : entry.name;
      if (entry.isDirectory() && relative !== '.git') {
        await this.walk(relative, files);
      } else if (entry.isFile() && RepositoryScanner.isCodeFile(relative)) {
        const absolute = path.join(this.root, relative);
        const language = RepositoryScanner.detectLanguage(relative);
        if (language && (await fs.stat(absolute)).size < MAX_FILE_BYTES) {
          files.push({ path: relative, content: await fs.readFile(absolute, 'utf-8'), language });
        }
      }
    }
  }
}
