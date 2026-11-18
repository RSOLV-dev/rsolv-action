import { inertInline } from '../utils/inert-markdown.js';

/**
 * The static hint is for the humans reading the issue. Prompt input must go
 * through withoutStaticHint: a "may be safe" nudge biases VALIDATE toward a
 * false-positive verdict.
 */
const LEAD = '> RSOLV static analysis thinks this may be safe because ';
const STATIC_HINT_CHARS = 500;

export function renderStaticHint(hint: string): string {
  return `${LEAD}${inertInline(hint, STATIC_HINT_CHARS)}`;
}

// inertInline keeps the hint on one line, so dropping that line drops all of it.
export function withoutStaticHint(body: string): string {
  return body.split('\n').filter(line => !line.startsWith(LEAD)).join('\n');
}
