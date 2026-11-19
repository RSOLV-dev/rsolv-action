import { inertInline } from '../utils/inert-markdown.js';

/**
 * The static hint is for the humans reading the issue. Prompt input must go
 * through withoutStaticHint: a "may be safe" nudge biases VALIDATE toward a
 * false-positive verdict.
 *
 * The hint renders as one quoted line between two HTML-comment markers, which
 * GitHub does not display. inertInline keeps the hint on that one line.
 */
const START = '<!-- rsolv:static-hint:start -->';
const END = '<!-- rsolv:static-hint:end -->';
const LEAD = '> RSOLV static analysis thinks this may be safe because ';
const STATIC_HINT_CHARS = 500;
// Hints filed before the markers: the bare quoted line, as a blockquote (at most three spaces in).
const LEGACY = /^ {0,3}> RSOLV static analysis thinks this may be safe because /;
const FENCE = /^ {0,3}(`{3,}|~{3,})/;

export function renderStaticHint(hint: string): string {
  return [START, `${LEAD}${inertInline(hint, STATIC_HINT_CHARS)}`, END].join('\n');
}

/**
 * Drops generated hint blocks and legacy hint lines. Lines inside fenced code
 * are customer content and always stay. An unterminated start marker drops only
 * its own line, never the customer text after it.
 */
export function withoutStaticHint(body: string): string {
  const lines = body.split('\n');
  const kept: string[] = [];
  let fence: RegExp | null = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (fence) {
      if (fence.test(line)) fence = null;
      kept.push(line);
      continue;
    }
    const open = FENCE.exec(line);
    if (open) {
      fence = new RegExp(`^ {0,3}${open[1][0]}{${open[1].length},}\\s*$`);
      kept.push(line);
    } else if (line.trim() === START) {
      if (lines[i + 2]?.trim() === END) i += 2;
    } else if (!LEGACY.test(line)) {
      kept.push(line);
    }
  }
  return kept.join('\n');
}
