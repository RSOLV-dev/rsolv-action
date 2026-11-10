/**
 * Structural whitelist for the v5 reusable workflows (RFC-150 §2.2). A role job is exactly the
 * approved checkout (where the role has one) and then the host step, with the host pins only in
 * the job's own literal env. Nothing else can run before the host, set its shell, or override a
 * pin, whatever YAML spelling it uses: the files parse with the failsafe schema and no anchors,
 * aliases or tags. The vitest in __tests__ runs this over the real workflows in CI.
 */
import { isDeepStrictEqual } from 'util';
import { EVENT_ALIAS, EVENT_MAPPING, EVENT_SCALAR, EVENT_SEQUENCE, FAILSAFE_SCHEMA, load, parseEvents } from 'js-yaml';

type Yaml = string | Yaml[] | Mapping;
interface Mapping {
  [key: string]: Yaml;
}

interface RoleSpec {
  job: string;
  checkout: boolean;
  decisionKeys: boolean;
}

export const ROLE_WORKFLOWS: Readonly<Record<string, RoleSpec>> = {
  'rsolv-scan.yml': { job: 'scan', checkout: true, decisionKeys: false },
  'rsolv-work.yml': { job: 'work', checkout: true, decisionKeys: false },
  'rsolv-verify.yml': { job: 'verify', checkout: true, decisionKeys: false },
  'rsolv-publish.yml': { job: 'publish', checkout: false, decisionKeys: true }
};

const CHECKOUT: Mapping = {
  uses: 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
  with: { 'persist-credentials': 'false', ref: '${{ github.sha }}' }
};

const PINS: Readonly<Record<string, RegExp>> = {
  RSOLV_HOST_VERSION: /^[0-9]+\.[0-9]+\.[0-9]+$/,
  RSOLV_HOST_SHA256_X64: /^[0-9a-f]{64}$/,
  RSOLV_HOST_SHA256_ARM64: /^[0-9a-f]{64}$/
};

/**
 * The decision key set rsolv-publish.yml pins for an environment until PR 8's key ceremony: two
 * all-zero keys that expired in 1970, under unpinned- kids. The publish job refuses it before
 * the role runs, and check-workflow-pins.sh accepts it only with --allow-placeholder-keys.
 */
export const placeholderKeySet = (environment: 'production' | 'staging'): string =>
  JSON.stringify(
    ['a', 'b'].map((slot) => ({
      kid: `unpinned-${environment}-${slot}`,
      public_key: 'A'.repeat(43),
      not_after: '1970-01-01'
    }))
  );

// The publish host step's key sets, by environment; it passes the API URL's one to the host.
const DECISION_KEY_SETS = {
  RSOLV_DECISION_KEYS_PRODUCTION: 'production',
  RSOLV_DECISION_KEYS_STAGING: 'staging'
} as const;

// What the host steps pass in; anything else (BASH_ENV, a pin) could change what bash runs.
const HOST_STEP_ENV = new Set(['RSOLV_API_URL', 'ISSUE', 'MAX_ISSUES', 'EXACT_RUNTIME_VERSIONS', 'GITHUB_TOKEN']);

// GitHub-hosted labels only, as a plain string: a self-hosted runner, a group or an expression
// would choose the environment the checkout and the host run in.
const RUNNERS = new Set(['ubuntu-latest']);

const TOP_LEVEL = new Set(['name', 'on', 'permissions', 'jobs']);
const ROLE_JOB = new Set(['runs-on', 'timeout-minutes', 'permissions', 'outputs', 'env', 'steps']);
const HOST_STEP = new Set(['id', 'name', 'env', 'run', 'shell']);

const ROLE_PERMISSIONS: Mapping = { contents: 'read', 'id-token': 'write' };
const ISSUE_WITH: Mapping = {
  issue: '${{ inputs.issue }}',
  api_url: '${{ inputs.api_url }}',
  exact_runtime_versions: '${{ inputs.exact_runtime_versions }}'
};
const ISSUE_JOBS: Readonly<Record<string, Mapping>> = {
  work: { uses: './.github/workflows/rsolv-work.yml', permissions: ROLE_PERMISSIONS, with: ISSUE_WITH },
  verify: {
    needs: 'work',
    if: 'needs.work.outputs.outcome == \'mitigated\'',
    uses: './.github/workflows/rsolv-verify.yml',
    permissions: ROLE_PERMISSIONS,
    with: ISSUE_WITH
  },
  // rsolv-host Roles.Publish: git data and refs (contents), the pull request (pull-requests),
  // labels and comments on the issue (issues), and its OIDC token for the run token and its
  // own check run (id-token).
  publish: {
    needs: 'verify',
    if: 'needs.verify.outputs.outcome == \'verified\'',
    uses: './.github/workflows/rsolv-publish.yml',
    permissions: { contents: 'write', 'pull-requests': 'write', issues: 'write', 'id-token': 'write' },
    with: { issue: '${{ inputs.issue }}', api_url: '${{ inputs.api_url }}' }
  }
};

const isMapping = (value: unknown): value is Mapping =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const extraKeys = (value: Mapping, allowed: ReadonlySet<string>): string[] =>
  Object.keys(value).filter((key) => !allowed.has(key));

/** Anchors, aliases and explicit tags, by event, before anything is constructed. */
function indirection(source: string): string[] {
  return parseEvents(source, {}).flatMap((event): string[] => {
    if (event.type === EVENT_ALIAS) return ['an alias is not allowed'];
    if (event.type !== EVENT_MAPPING && event.type !== EVENT_SEQUENCE && event.type !== EVENT_SCALAR) return [];
    const found: string[] = [];
    if (event.anchorStart >= 0) found.push('an anchor is not allowed');
    if (event.tagStart >= 0) found.push('an explicit tag is not allowed');
    return found;
  });
}

function literalEnv(where: string, env: Yaml | undefined): Mapping | string {
  if (env === undefined) return {};
  if (!isMapping(env) || Object.values(env).some((value) => typeof value !== 'string')) {
    return `${where}: env must be a mapping of names to literal strings`;
  }
  return env;
}

function roleJob(file: string, spec: RoleSpec, job: Yaml | undefined): string[] {
  if (!isMapping(job)) return [`${file}: job ${spec.job} must be a mapping`];
  const found = extraKeys(job, ROLE_JOB).map((key) => `${file}: job ${spec.job} may not set ${key}`);
  const runsOn = job['runs-on'];
  if (typeof runsOn !== 'string' || !RUNNERS.has(runsOn)) {
    found.push(`${file}: job ${spec.job} runs-on must be one of ${[...RUNNERS].join(', ')}, as a plain string`);
  }

  const env = literalEnv(`${file}: job ${spec.job}`, job.env);
  if (typeof env === 'string') {
    found.push(env);
  } else {
    if (!isDeepStrictEqual(Object.keys(env).sort(), Object.keys(PINS).sort())) {
      found.push(`${file}: the job env must hold exactly ${Object.keys(PINS).join(', ')}`);
    }
    for (const [name, format] of Object.entries(PINS)) {
      const value = env[name];
      if (typeof value !== 'string' || !format.test(value)) found.push(`${file}: ${name} must be a literal ${format}`);
    }
  }

  const steps = job.steps;
  const expected = spec.checkout ? '[checkout, host]' : '[host]';
  if (!Array.isArray(steps) || steps.length !== (spec.checkout ? 2 : 1)) {
    return [...found, `${file}: steps must be ${expected}`];
  }
  if (spec.checkout && !isDeepStrictEqual(steps[0], CHECKOUT)) {
    found.push(`${file}: steps must be ${expected}; the first is not the approved checkout`);
  }
  return [...found, ...hostStep(file, spec, steps[steps.length - 1])];
}

// One pinned key: a lowercase kid, a canonical unpadded base64url 32-byte public key
// (RsolvCore.Decision.parse_keys), a real calendar date; and nothing a placeholder uses.
function keyValid(key: unknown): boolean {
  if (!isMapping(key) || !isDeepStrictEqual(Object.keys(key), ['kid', 'public_key', 'not_after'])) return false;
  const { kid, public_key: publicKey, not_after: notAfter } = key;
  if (typeof kid !== 'string' || typeof publicKey !== 'string' || typeof notAfter !== 'string') return false;
  const day = Date.parse(`${notAfter}T00:00:00Z`);
  return (
    /^[a-z0-9][a-z0-9-]{0,63}$/.test(kid) &&
    !kid.startsWith('unpinned-') &&
    publicKey !== 'A'.repeat(43) &&
    Buffer.from(publicKey, 'base64url').length === 32 &&
    Buffer.from(publicKey, 'base64url').toString('base64url') === publicKey &&
    /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(notAfter) &&
    !Number.isNaN(day) &&
    new Date(day).toISOString().startsWith(notAfter)
  );
}

/**
 * A key set is its environment's placeholder, or compact JSON (one spelling, so no duplicate
 * members) of at least two valid keys with unique kids and public keys.
 */
function keySetValid(environment: 'production' | 'staging', value: string): boolean {
  if (value === placeholderKeySet(environment)) return true;
  let keys: unknown;
  try {
    keys = JSON.parse(value);
  } catch {
    return false;
  }
  if (!Array.isArray(keys) || keys.length < 2 || JSON.stringify(keys) !== value || !keys.every(keyValid)) return false;
  const list: Mapping[] = keys;
  const unique = (field: string): boolean => new Set(list.map((key) => key[field])).size === list.length;
  return unique('kid') && unique('public_key');
}

function hostStep(file: string, spec: RoleSpec, step: Yaml | undefined): string[] {
  if (!isMapping(step)) return [`${file}: the host step must be a mapping`];
  const found = extraKeys(step, HOST_STEP).map((key) => `${file}: the host step may not set ${key}`);
  if (step.id !== 'host') found.push(`${file}: the host step must have id: host`);
  if (typeof step.run !== 'string' || !step.run.startsWith('# BEGIN install-host\n')) {
    found.push(`${file}: the host step must start with the install-host block`);
  }
  if (step.shell !== undefined && step.shell !== 'bash') found.push(`${file}: the host step's shell must be bash`);

  const env = literalEnv(`${file}: the host step`, step.env);
  if (typeof env === 'string') return [...found, env];
  const keySets = spec.decisionKeys ? Object.entries(DECISION_KEY_SETS) : [];
  const allowed = new Set([...HOST_STEP_ENV, ...keySets.map(([name]) => name)]);
  found.push(...extraKeys(env, allowed).map((key) => `${file}: the host step env may not set ${key}`));
  for (const [name, environment] of keySets) {
    const value = env[name];
    if (typeof value !== 'string' || !keySetValid(environment, value)) {
      found.push(`${file}: ${name} must be the ${environment} placeholder key set or a literal key set (RFC-150 §6.4)`);
    }
  }
  return found;
}

function issueJobs(file: string, jobs: Mapping): string[] {
  if (!isDeepStrictEqual(Object.keys(jobs).sort(), Object.keys(ISSUE_JOBS).sort())) {
    return [`${file}: jobs must be exactly ${Object.keys(ISSUE_JOBS).join(', ')}`];
  }
  return Object.entries(ISSUE_JOBS)
    .filter(([name, expected]) => !isDeepStrictEqual(jobs[name], expected))
    .map(([name]) => `${file}: job ${name} must call its local role workflow with the approved with: and permissions`);
}

/** Every structural violation in one v5 workflow file; empty when it conforms. */
export function structureViolations(file: string, source: string): string[] {
  const spec = ROLE_WORKFLOWS[file];
  if (spec === undefined && file !== 'rsolv-issue.yml') return [`${file}: not a v5 workflow`];

  let doc: unknown;
  try {
    const hidden = indirection(source);
    if (hidden.length > 0) return hidden.map((reason) => `${file}: ${reason}`);
    doc = load(source, { schema: FAILSAFE_SCHEMA, filename: file });
  } catch (error) {
    return [`${file}: ${error instanceof Error ? error.message : String(error)}`];
  }
  if (!isMapping(doc)) return [`${file}: not a mapping`];

  const found = extraKeys(doc, TOP_LEVEL).map((key) => `${file}: top-level ${key} is not allowed`);
  if (!isMapping(doc.on) || !isDeepStrictEqual(Object.keys(doc.on), ['workflow_call'])) {
    found.push(`${file}: on must be workflow_call only`);
  }
  if (!isDeepStrictEqual(doc.permissions, {})) found.push(`${file}: top-level permissions must be {}`);
  if (!isMapping(doc.jobs)) return [...found, `${file}: jobs must be a mapping`];

  if (spec === undefined) return [...found, ...issueJobs(file, doc.jobs)];
  if (!isDeepStrictEqual(Object.keys(doc.jobs), [spec.job])) {
    return [...found, `${file}: jobs must be exactly ${spec.job}`];
  }
  return [...found, ...roleJob(file, spec, doc.jobs[spec.job])];
}
