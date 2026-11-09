import { describe, expect, test } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { ROLE_WORKFLOWS, structureViolations } from '../v5-structure';

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
        expect.stringContaining('verify')
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

  test('an unknown workflow file is refused', () => {
    expect(structureViolations('rsolv-other.yml', 'name: x\n')).toContainEqual(
      expect.stringContaining('not a v5 workflow')
    );
  });
});
