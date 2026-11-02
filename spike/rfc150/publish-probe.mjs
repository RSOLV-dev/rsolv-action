// RFC-150 step 1 spike: build the RED and fix commits through the Git Data API from
// a fixed change set, check them directory by directory, then open a PR.
// Runs in the publish job with GITHUB_TOKEN only. Writes evidence JSON to argv[2].
import { writeFileSync } from 'node:fs';
import { blobSha, expectations, diffDir } from './changeset.mjs';

const { GH_TOKEN, GITHUB_API_URL, GITHUB_REPOSITORY, GITHUB_SHA, GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT, ISSUE } = process.env;

async function api(method, path, body) {
  const res = await fetch(`${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}${path}`, {
    method,
    headers: { authorization: `Bearer ${GH_TOKEN}`, accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28' },
    body: body && JSON.stringify(body),
  });
  return { status: res.status, json: await res.json().catch(() => null) };
}

// Throws on any non-2xx response from a call whose result the rest of the probe depends on.
function must(step, res) {
  if (res.status >= 300) throw new Error(`${step}: HTTP ${res.status} ${res.json?.message ?? ''}`);
  return res;
}

const text = (s) => Buffer.from(s, 'utf8');
const RED = [{ path: 'test/red_test.txt', op: 'add', bytes: text('red\n') }];
const FIX = [
  { path: 'bin/run.sh', op: 'modify', bytes: text('#!/bin/sh\necho fixed\n') },
  { path: 'crlf.txt', op: 'modify', bytes: text('line one\r\nline two, fixed\r\n') },
  { path: 'empty.txt', op: 'add', bytes: Buffer.alloc(0) },
  { path: 'no-newline.txt', op: 'add', bytes: text('no trailing newline') },
  { path: 'docs/ünïcode-2.md', op: 'add', bytes: text('ünïcode\n') },
  { path: 'src/old.txt', op: 'delete' },
];
const dirOf = (path) => (path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : '');
const nameOf = (path) => path.slice(path.lastIndexOf('/') + 1);

async function treeEntries(rootTreeSha, dir) {
  let sha = rootTreeSha;
  for (const part of dir ? dir.split('/') : []) {
    const { json } = must(`GET tree ${sha}`, await api('GET', `/git/trees/${sha}`));
    const entry = json.tree.find((e) => e.path === part && e.type === 'tree');
    if (!entry) return [];
    sha = entry.sha;
  }
  return must(`GET tree ${sha}`, await api('GET', `/git/trees/${sha}`)).json.tree;
}

async function baseFacts(baseTree, changes) {
  const facts = {};
  for (const c of changes) {
    const e = (await treeEntries(baseTree, dirOf(c.path))).find((x) => x.path === nameOf(c.path));
    facts[c.path] = e ? { exists: true, mode: e.mode, sha: e.sha, type: e.type } : { exists: false };
  }
  return facts;
}

async function commit(parentSha, parentTree, changes, facts, message, mismatches) {
  const tree = [];
  const signed = [];
  for (const c of changes) {
    if (c.op === 'delete') {
      tree.push({ path: c.path, mode: facts[c.path].mode, type: 'blob', sha: null });
      signed.push({ path: c.path, op: 'delete' });
      continue;
    }
    const mode = c.op === 'modify' ? facts[c.path].mode : '100644';
    const expected = blobSha(c.bytes);
    const blobRes = must(`POST blob ${c.path}`, await api('POST', '/git/blobs', { content: c.bytes.toString('base64'), encoding: 'base64' }));
    if (blobRes.json?.sha !== expected) mismatches.push({ path: c.path, expected, got: blobRes.json?.sha ?? null });
    tree.push({ path: c.path, mode, type: 'blob', sha: expected });
    signed.push({ path: c.path, op: c.op, mode, new_blob_sha: expected });
  }
  const t = must('POST tree', await api('POST', '/git/trees', { base_tree: parentTree, tree }));
  const k = must('POST commit', await api('POST', '/git/commits', { message, tree: t.json.sha, parents: [parentSha] }));
  const problems = [];
  for (const [dir, want] of expectations(signed)) {
    problems.push(...diffDir(want, await treeEntries(t.json.sha, dir)).map((p) => ({ dir, ...p })));
  }
  return { sha: k.json.sha, tree: t.json.sha, problems };
}

const mismatches = [];
let facts = null;
let red = null;
let fix = null;
let branch = null;
let ref = null;
let pr = null;

try {
  const baseTree = must('GET base commit', await api('GET', `/git/commits/${GITHUB_SHA}`)).json.tree.sha;
  facts = await baseFacts(baseTree, [...RED, ...FIX]);
  red = await commit(GITHUB_SHA, baseTree, RED, facts, `test: RED for spike issue ${ISSUE}`, mismatches);
  fix = await commit(red.sha, red.tree, FIX, facts, `fix: spike issue ${ISSUE}`, mismatches);
  branch = `rsolv/spike-${GITHUB_RUN_ID}-${ISSUE}-a${GITHUB_RUN_ATTEMPT}`;
  ref = await api('POST', '/git/refs', { ref: `refs/heads/${branch}`, sha: fix.sha });
  pr = await api('POST', '/pulls', {
    title: `RFC-150 spike: issue ${ISSUE}`,
    head: branch,
    base: 'main',
    body: 'Opened by the spike publish job with GITHUB_TOKEN. Throwaway; close freely.',
  });

  writeFileSync(process.argv[2], JSON.stringify({
    base_facts: facts,
    blob_sha_mismatches: mismatches,
    red_problems: red.problems,
    fix_problems: fix.problems,
    branch,
    ref_status: ref.status,
    pr_status: pr.status,
    pr_number: pr.json?.number ?? null,
    pr_error: pr.status === 201 ? null : (pr.json?.message ?? null),
  }, null, 2));
} catch (err) {
  writeFileSync(process.argv[2], JSON.stringify({
    base_facts: facts,
    blob_sha_mismatches: mismatches,
    red_problems: red?.problems ?? null,
    fix_problems: fix?.problems ?? null,
    branch,
    ref_status: ref?.status ?? null,
    pr_status: pr?.status ?? null,
    pr_number: pr?.json?.number ?? null,
    pr_error: pr && pr.status !== 201 ? (pr.json?.message ?? null) : null,
    error: err.message,
  }, null, 2));
  process.exit(1);
}
