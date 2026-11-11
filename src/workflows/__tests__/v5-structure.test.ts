import { describe, expect, test } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { placeholderKeySet, ROLE_WORKFLOWS, structureViolations } from '../v5-structure';

const workflowDir = resolve(__dirname, '../../../.github/workflows');
const read = (file: string): string => readFileSync(resolve(workflowDir, file), 'utf8');

// Each fixture edits one real workflow, so a test fails only for the bypass it names.
const edited = (file: string, from: RegExp | string, to: string): string => {
  const source = read(file);
  const result = source.replace(from, to);
  if (result === source) throw new Error(`fixture edit did not apply to ${file}: ${String(from)}`);
  return result;
};

const ZERO = '0'.repeat(64);

describe('structureViolations', () => {
  describe('when given the real v5 workflows', () => {
    test.each([...Object.keys(ROLE_WORKFLOWS), 'rsolv-issue.yml'])('%s has none', (file) => {
      expect(structureViolations(file, read(file))).toEqual([]);
    });
  });

  describe('when a role workflow tries to run something before the host', () => {
    test('a folded env expression is refused', () => {
      const source = edited(
        'rsolv-verify.yml',
        / {8}env:\n {10}RSOLV_API_URL: .*\n {10}ISSUE: .*\n {10}EXACT_RUNTIME_VERSIONS: .*\n/,
        '        env: >-\n          ${{ fromJSON(inputs.api_url) }}\n'
      );
      expect(structureViolations('rsolv-verify.yml', source)).toContainEqual(
        expect.stringContaining('env must be a mapping')
      );
    });

    test('an earlier step writing to $GITHUB_ENV is refused', () => {
      const source = edited(
        'rsolv-verify.yml',
        '      - id: host\n',
        '      - run: env | sed -n "s/^\\(RSOLV_HOST_[A-Z0-9_]*\\)=.*/\\1=x/p" >>"$GITHUB_ENV"\n      - id: host\n'
      );
      expect(structureViolations('rsolv-verify.yml', source)).toContainEqual(
        expect.stringContaining('steps must be')
      );
    });

    test('a workflow-level defaults.run.shell is refused', () => {
      const source = edited('rsolv-verify.yml', /^jobs:$/m, 'defaults:\n  run:\n    shell: python {0}\njobs:');
      expect(structureViolations('rsolv-verify.yml', source)).toContainEqual(
        expect.stringContaining('defaults')
      );
    });

    test('a job-level defaults.run.shell is refused', () => {
      const source = edited('rsolv-verify.yml', /^ {4}steps:$/m, '    defaults:\n      run:\n        shell: python {0}\n    steps:');
      expect(structureViolations('rsolv-verify.yml', source)).toContainEqual(
        expect.stringContaining('defaults')
      );
    });

    test('an extra step before the host is refused', () => {
      const source = edited(
        'rsolv-verify.yml',
        '      - id: host\n',
        '      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0\n      - id: host\n'
      );
      expect(structureViolations('rsolv-verify.yml', source)).toContainEqual(
        expect.stringContaining('steps must be')
      );
    });

    test('a step after the host is refused', () => {
      const source = `${read('rsolv-verify.yml')}      - run: echo after\n`;
      expect(structureViolations('rsolv-verify.yml', source)).toContainEqual(
        expect.stringContaining('steps must be')
      );
    });

    test('a checkout with other inputs is refused', () => {
      const source = edited('rsolv-verify.yml', '          persist-credentials: false\n', '          persist-credentials: true\n');
      expect(structureViolations('rsolv-verify.yml', source)).toContainEqual(
        expect.stringContaining('checkout')
      );
    });

    test('a host step with shell: python is refused', () => {
      const source = edited('rsolv-verify.yml', '      - id: host\n', '      - id: host\n        shell: python {0}\n');
      expect(structureViolations('rsolv-verify.yml', source)).toContainEqual(
        expect.stringContaining('shell')
      );
    });

    test('a host step with shell: bash is accepted', () => {
      const source = edited('rsolv-verify.yml', '      - id: host\n', '      - id: host\n        shell: bash\n');
      expect(structureViolations('rsolv-verify.yml', source)).toEqual([]);
    });

    test('BASH_ENV in the host step env is refused', () => {
      const source = edited('rsolv-verify.yml', /^( {10}ISSUE: .*)$/m, '$1\n          BASH_ENV: ${{ inputs.api_url }}');
      expect(structureViolations('rsolv-verify.yml', source)).toContainEqual(
        expect.stringContaining('BASH_ENV')
      );
    });

    test('a host step with an if: is refused', () => {
      const source = edited('rsolv-verify.yml', '      - id: host\n', '      - id: host\n        if: github.event_name == \'push\'\n');
      expect(structureViolations('rsolv-verify.yml', source)).toContainEqual(
        expect.stringContaining('host step')
      );
    });

    test('a job container is refused', () => {
      const source = edited('rsolv-verify.yml', /^ {4}steps:$/m, '    container: node:22\n    steps:');
      expect(structureViolations('rsolv-verify.yml', source)).toContainEqual(
        expect.stringContaining('container')
      );
    });
  });

  describe('when a role job picks its own runner', () => {
    test.each([
      ['literal self-hosted', 'self-hosted'],
      ['an array of self-hosted labels', '[self-hosted, linux]'],
      ['an expression', '${{ inputs.runner }}'],
      ['a group mapping', '{group: x}'],
      ['an unlisted hosted label', 'windows-latest']
    ])('%s is refused', (_name, runsOn) => {
      const source = edited('rsolv-verify.yml', /^ {4}runs-on: ubuntu-latest$/m, `    runs-on: ${runsOn}`);
      expect(structureViolations('rsolv-verify.yml', source)).toContainEqual(
        expect.stringContaining('runs-on')
      );
    });
  });

  describe('when the YAML hides structure', () => {
    test('an anchor is refused', () => {
      const source = edited('rsolv-verify.yml', /^ {4}env:$/m, '    env: &pins');
      expect(structureViolations('rsolv-verify.yml', source)).toContainEqual(
        expect.stringContaining('anchor')
      );
    });

    test('an alias is refused', () => {
      const source = edited('rsolv-verify.yml', /^ {10}ISSUE: .*$/m, '          ISSUE: *issue');
      expect(structureViolations('rsolv-verify.yml', source)).toContainEqual(
        expect.stringMatching(/alias|unidentified/)
      );
    });

    test('an explicit tag is refused', () => {
      const source = edited('rsolv-verify.yml', /^ {10}ISSUE: /m, '          ISSUE: !!str ');
      expect(structureViolations('rsolv-verify.yml', source)).toContainEqual(
        expect.stringContaining('tag')
      );
    });

    test('a duplicate key is refused', () => {
      const source = edited('rsolv-verify.yml', /^( {6}RSOLV_HOST_SHA256_X64: .*)$/m, `$1\n      RSOLV_HOST_SHA256_X64: "${ZERO}"`);
      expect(structureViolations('rsolv-verify.yml', source)).toContainEqual(
        expect.stringContaining('duplicated')
      );
    });
  });

  describe('when a host pin is defined anywhere but the role job env', () => {
    test('a pin key in a step env is refused', () => {
      const source = edited('rsolv-verify.yml', /^( {10}ISSUE: .*)$/m, `$1\n          RSOLV_HOST_SHA256_X64: "${'a'.repeat(64)}"`);
      expect(structureViolations('rsolv-verify.yml', source)).toContainEqual(
        expect.stringContaining('RSOLV_HOST_SHA256_X64')
      );
    });

    test('a workflow-level env is refused', () => {
      const source = edited('rsolv-verify.yml', /^jobs:$/m, `env:\n  RSOLV_HOST_SHA256_X64: "${ZERO}"\njobs:`);
      expect(structureViolations('rsolv-verify.yml', source)).toContainEqual(
        expect.stringContaining('top-level')
      );
    });

    test('a second job is refused', () => {
      const source = `${read('rsolv-verify.yml')}  other:\n    runs-on: ubuntu-latest\n    env:\n      RSOLV_HOST_SHA256_X64: "${ZERO}"\n    steps:\n      - run: "true"\n`;
      expect(structureViolations('rsolv-verify.yml', source)).toContainEqual(
        expect.stringContaining('jobs must be')
      );
    });

    test('a malformed pin value is refused', () => {
      const source = edited('rsolv-verify.yml', /^ {6}RSOLV_HOST_VERSION: .*$/m, '      RSOLV_HOST_VERSION: "${{ inputs.api_url }}"');
      expect(structureViolations('rsolv-verify.yml', source)).toContainEqual(
        expect.stringContaining('RSOLV_HOST_VERSION')
      );
    });

    test('an extra job env key is refused', () => {
      const source = edited('rsolv-verify.yml', /^( {6}RSOLV_HOST_VERSION: .*)$/m, '$1\n      BASH_ENV: /tmp/x');
      expect(structureViolations('rsolv-verify.yml', source)).toContainEqual(
        expect.stringContaining('job env')
      );
    });
  });

  describe('when rsolv-issue.yml calls something other than the role workflows', () => {
    test('a foreign reusable workflow is refused', () => {
      const source = edited('rsolv-issue.yml', 'uses: ./.github/workflows/rsolv-verify.yml', 'uses: evil/repo/.github/workflows/x.yml@main');
      expect(structureViolations('rsolv-issue.yml', source)).toContainEqual(
        expect.stringContaining('verify')
      );
    });

    test('an extra with: key is refused', () => {
      const source = `${read('rsolv-issue.yml')}      extra: x\n`;
      expect(structureViolations('rsolv-issue.yml', source)).toContainEqual(
        expect.stringContaining('publish')
      );
    });

    test('widened permissions are refused', () => {
      const source = edited('rsolv-issue.yml', /( {2}verify:[\s\S]*?) {6}contents: read/, '$1      contents: write');
      expect(structureViolations('rsolv-issue.yml', source)).toContainEqual(
        expect.stringContaining('verify')
      );
    });

    test('a job with steps is refused', () => {
      const source = `${read('rsolv-issue.yml')}  sneaky:\n    runs-on: ubuntu-latest\n    steps:\n      - run: "true"\n`;
      expect(structureViolations('rsolv-issue.yml', source)).toContainEqual(
        expect.stringContaining('jobs must be')
      );
    });
  });

  describe('when publish is gated on anything but a verified verify job', () => {
    test.each([
      ['the work job\'s has_patch', 'needs.work.outputs.has_patch == \'true\''],
      ['the work job\'s outcome', 'needs.work.outputs.outcome == \'verified\''],
      ['always()', 'always()'],
      ['a verify outcome other than verified', 'needs.verify.outputs.outcome != \'rejected\'']
    ])('%s is refused', (_name, condition) => {
      const source = edited('rsolv-issue.yml', 'if: needs.verify.outputs.outcome == \'verified\'', `if: ${condition}`);
      expect(structureViolations('rsolv-issue.yml', source)).toContainEqual(expect.stringContaining('publish'));
    });

    test('a publish job that does not need verify is refused', () => {
      const source = edited('rsolv-issue.yml', /^( {4})needs: verify$/m, '$1needs: work');
      expect(structureViolations('rsolv-issue.yml', source)).toContainEqual(expect.stringContaining('publish'));
    });

    test('a publish job with an extra permission is refused', () => {
      const source = edited('rsolv-issue.yml', /( {2}publish:[\s\S]*? {6}issues: write\n)/, '$1      actions: write\n');
      expect(structureViolations('rsolv-issue.yml', source)).toContainEqual(expect.stringContaining('publish'));
    });
  });

  describe('when the publish job pins its decision keys', () => {
    // Arbitrary 32-byte values: the whitelist checks the encoding, not the curve.
    const key = (fill: number): string => Buffer.alloc(32, fill).toString('base64url');
    const realSet = (env: string): string =>
      JSON.stringify([
        { kid: `${env}-2026-12-01-a`, public_key: key(1), not_after: '2027-03-01' },
        { kid: `${env}-2026-12-01-b`, public_key: key(2), not_after: '2027-03-01' }
      ]);
    const pinned = (name: string, value: string, source = read('rsolv-publish.yml')): string => {
      const result = source.replace(new RegExp(`^( {10}${name}: ).*$`, 'm'), (_line, key: string) => `${key}${value}`);
      if (result === source) throw new Error(`fixture edit did not apply: ${name}`);
      return result;
    };

    test('real production and staging sets are accepted', () => {
      const source = pinned('RSOLV_DECISION_KEYS_STAGING', `'${realSet('staging')}'`, pinned('RSOLV_DECISION_KEYS_PRODUCTION', `'${realSet('prod')}'`));
      expect(structureViolations('rsolv-publish.yml', source)).toEqual([]);
    });

    test('a mid-rotation set of four keys is accepted', () => {
      const four = JSON.stringify([
        ...JSON.parse(realSet('prod')),
        { kid: 'prod-2026-10-01-a', public_key: key(3), not_after: '2027-01-01' },
        { kid: 'prod-2026-10-01-b', public_key: key(4), not_after: '2027-01-01' }
      ]);
      expect(structureViolations('rsolv-publish.yml', pinned('RSOLV_DECISION_KEYS_PRODUCTION', `'${four}'`))).toEqual([]);
    });

    const prod = realSet('prod');
    test.each([
      ['an expression', '${{ inputs.decision_keys }}'],
      ['an empty set', '\'[]\''],
      ['a single key', `'${JSON.stringify([JSON.parse(prod)[0]])}'`],
      ['an all-zero key under a real kid', `'${prod.replace(key(1), 'A'.repeat(43))}'`],
      ['a placeholder kid with a real key', `'${prod.replace('prod-2026-12-01-a', 'unpinned-production-a')}'`],
      ['a non-canonical public key', `'${prod.replace(key(1), `${key(1).slice(0, 42)}B`)}'`],
      ['a duplicate kid', `'${prod.replace('prod-2026-12-01-b', 'prod-2026-12-01-a')}'`],
      ['a duplicate public key', `'${prod.replace(key(2), key(1))}'`],
      ['an extra field', `'${prod.replace('"not_after":"2027-03-01"}', '"not_after":"2027-03-01","use":"x"}')}'`],
      ['JSON with spaces', `'${prod.replace(/,"/g, ', "')}'`],
      ['a malformed not_after', `'${prod.replace('2027-03-01', '2027-3-1')}'`],
      ['a not_after past the end of its month', `'${prod.replace('2027-03-01', '2027-02-30')}'`],
      ['a not_after in month 13', `'${prod.replace('2027-03-01', '2027-13-01')}'`],
      ['the staging placeholder', `'${placeholderKeySet('staging')}'`]
    ])('%s for production is refused', (_name, value) => {
      expect(structureViolations('rsolv-publish.yml', pinned('RSOLV_DECISION_KEYS_PRODUCTION', value))).toContainEqual(
        expect.stringContaining('RSOLV_DECISION_KEYS_PRODUCTION')
      );
    });

    test('a missing staging set is refused', () => {
      const source = edited('rsolv-publish.yml', /^ {10}RSOLV_DECISION_KEYS_STAGING: .*\n/m, '');
      expect(structureViolations('rsolv-publish.yml', source)).toContainEqual(
        expect.stringContaining('RSOLV_DECISION_KEYS_STAGING')
      );
    });

    test('the single RSOLV_DECISION_KEYS variable is refused', () => {
      const source = edited('rsolv-publish.yml', /^( {10}ISSUE: .*)$/m, '$1\n          RSOLV_DECISION_KEYS: \'[]\'');
      expect(structureViolations('rsolv-publish.yml', source)).toContainEqual(
        expect.stringContaining('may not set RSOLV_DECISION_KEYS')
      );
    });

    test('a decision key set in another role is refused', () => {
      const source = edited('rsolv-verify.yml', /^( {10}ISSUE: .*)$/m, `$1\n          RSOLV_DECISION_KEYS_PRODUCTION: '${prod}'`);
      expect(structureViolations('rsolv-verify.yml', source)).toContainEqual(
        expect.stringContaining('RSOLV_DECISION_KEYS_PRODUCTION')
      );
    });
  });

  test('an unknown workflow file is refused', () => {
    expect(structureViolations('rsolv-other.yml', 'name: x\n')).toContainEqual(
      expect.stringContaining('not a v5 workflow')
    );
  });
});
