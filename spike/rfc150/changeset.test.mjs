import { test } from 'node:test';
import assert from 'node:assert/strict';
import { blobSha, expectations, diffDir } from './changeset.mjs';

test('blobSha matches git hash-object', () => {
  assert.equal(blobSha(Buffer.alloc(0)), 'e69de29bb2d1d6434b8b29ae775ad8c2e48c5391');
  assert.equal(blobSha(Buffer.from('hello\n')), 'ce013625030ba8dba906f756967f9e9ca394464a');
});

test('expectations groups entries by directory and marks deletes as null', () => {
  const e = expectations([
    { path: 'a.txt', op: 'add', mode: '100644', new_blob_sha: 'x' },
    { path: 'd/e/f.txt', op: 'delete' },
  ]);
  assert.deepEqual(e.get(''), new Map([['a.txt', { mode: '100644', sha: 'x' }]]));
  assert.deepEqual(e.get('d/e'), new Map([['f.txt', null]]));
});

test('diffDir reports mode mismatches, survivors of deletes and missing entries', () => {
  const want = new Map([['a', { mode: '100755', sha: 's' }], ['b', null], ['c', { mode: '100644', sha: 't' }]]);
  const got = [{ path: 'a', mode: '100644', sha: 's' }, { path: 'b', mode: '100644', sha: 'u' }];
  assert.deepEqual(diffDir(want, got).map((p) => [p.name, p.problem]), [['a', 'mismatch'], ['b', 'present'], ['c', 'missing']]);
});

test('diffDir is empty when the tree matches', () => {
  assert.deepEqual(diffDir(new Map([['a', { mode: '100644', sha: 's' }]]), [{ path: 'a', mode: '100644', sha: 's' }]), []);
});
