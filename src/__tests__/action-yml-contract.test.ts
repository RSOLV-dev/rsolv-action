import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';

// Contract tests for action.yml — the action's public surface.
// Why: inputs declared without env-block wiring become phantom controls
// (declared, accepted, never propagated to the container). See
// memory/feedback_phantom_input_inert.md for the latent-bug pattern.

const __dirname = dirname(fileURLToPath(import.meta.url));

interface ActionManifest {
  inputs?: Record<string, { description?: string; required?: boolean; default?: string }>;
  runs?: { env?: Record<string, string> };
}

function loadActionManifest(): ActionManifest {
  const path = join(__dirname, '..', '..', 'action.yml');
  return yaml.load(readFileSync(path, 'utf8')) as ActionManifest;
}

describe('action.yml contract', () => {
  describe('GITHUB_TOKEN propagation', () => {
    test('runs.env maps GITHUB_TOKEN from inputs.github-token', () => {
      const manifest = loadActionManifest();
      const env = manifest.runs?.env ?? {};
      expect(env.GITHUB_TOKEN).toBeDefined();
      // Bracket form is required because `inputs.github-token` parses as subtraction.
      expect(env.GITHUB_TOKEN).toMatch(/inputs\['github-token'\]/);
    });
  });

  describe('claude_max_turns removal', () => {
    test('input is no longer declared (deprecated, server-side controlled)', () => {
      const manifest = loadActionManifest();
      expect(manifest.inputs?.claude_max_turns).toBeUndefined();
    });

    test('runs.env no longer wires RSOLV_CLAUDE_MAX_TURNS', () => {
      const manifest = loadActionManifest();
      expect(manifest.runs?.env?.RSOLV_CLAUDE_MAX_TURNS).toBeUndefined();
    });
  });
});
