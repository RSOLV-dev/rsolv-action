// RFC-150 step 1 spike helpers: git blob SHAs and per-directory tree expectations.
import { createHash } from 'node:crypto';

export const blobSha = (bytes) =>
  createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');

// Map(dir -> Map(name -> {mode, sha} | null)); null means the entry must be absent.
export function expectations(changes) {
  const byDir = new Map();
  for (const c of changes) {
    const i = c.path.lastIndexOf('/');
    const dir = i < 0 ? '' : c.path.slice(0, i);
    if (!byDir.has(dir)) byDir.set(dir, new Map());
    byDir.get(dir).set(c.path.slice(i + 1), c.op === 'delete' ? null : { mode: c.mode, sha: c.new_blob_sha });
  }
  return byDir;
}

// entries: one directory's entries from GET /git/trees/{sha} (non-recursive).
export function diffDir(expected, entries) {
  const actual = new Map(entries.map((e) => [e.path, e]));
  const problems = [];
  for (const [name, want] of expected) {
    const got = actual.get(name);
    if (want === null) {
      if (got) problems.push({ name, problem: 'present' });
    } else if (!got) {
      problems.push({ name, problem: 'missing' });
    } else if (got.mode !== want.mode || got.sha !== want.sha) {
      problems.push({ name, problem: 'mismatch', want, got: { mode: got.mode, sha: got.sha } });
    }
  }
  return problems;
}
