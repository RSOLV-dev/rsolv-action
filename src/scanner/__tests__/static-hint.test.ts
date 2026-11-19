import { describe, it, expect } from 'vitest';
import { renderStaticHint, withoutStaticHint } from '../static-hint.js';

const START = '<!-- rsolv:static-hint:start -->';
const END = '<!-- rsolv:static-hint:end -->';
const LEGACY = '> RSOLV static analysis thinks this may be safe because Safe pattern detected';

const body = (...lines: string[]): string => lines.join('\n');

describe('renderStaticHint', () => {
  it('wraps the quoted hint in generated markers, which GitHub does not render', () => {
    expect(renderStaticHint('it is parameterized')).toBe(
      body(START, '> RSOLV static analysis thinks this may be safe because it is parameterized', END)
    );
  });
});

describe('withoutStaticHint', () => {
  describe('with a generated hint block', () => {
    it('drops the block and keeps everything around it', () => {
      expect(withoutStaticHint(body('before', renderStaticHint('x'), 'after'))).toBe(body('before', 'after'));
    });

    it('drops every block when the body carries several', () => {
      const text = body('a', renderStaticHint('x'), 'b', renderStaticHint('y'), 'c');

      expect(withoutStaticHint(text)).toBe(body('a', 'b', 'c'));
    });

    it('drops a block whose hint line was indented', () => {
      const text = body('a', START, ' > RSOLV static analysis thinks this may be safe because x', END, 'b');

      expect(withoutStaticHint(text)).toBe(body('a', 'b'));
    });

    it('drops a block in a body GitHub handed back with CRLF', () => {
      const text = body('a', renderStaticHint('x'), 'b').replace(/\n/g, '\r\n');

      expect(withoutStaticHint(text)).toBe('a\r\nb');
    });
  });

  describe('with a marker block indented four spaces, where it is a code block', () => {
    it('keeps it as customer content', () => {
      const text = body('a', '', `    ${START}`, '    > RSOLV static analysis thinks this may be safe because x', `    ${END}`, 'b');

      expect(withoutStaticHint(text)).toBe(text);
    });
  });

  describe('with an unterminated start marker', () => {
    it('drops the marker line alone and never the customer text after it', () => {
      const text = body('a', START, 'customer line one', 'customer line two');

      expect(withoutStaticHint(text)).toBe(body('a', 'customer line one', 'customer line two'));
    });
  });

  describe('with a hint filed before the markers existed', () => {
    it.each([
      ['at line start', LEGACY],
      ['indented by up to three spaces', `   ${LEGACY}`]
    ])('drops it %s', (_label, line) => {
      expect(withoutStaticHint(body('a', line, 'b'))).toBe(body('a', 'b'));
    });

    it('keeps it indented four spaces, where it is a code block', () => {
      const text = body('a', '', `    ${LEGACY}`);

      expect(withoutStaticHint(text)).toBe(text);
    });
  });

  describe('inside a fenced code block', () => {
    it.each([
      ['backtick', '```'],
      ['tilde', '~~~']
    ])('keeps a customer line that matches the hint, in a %s fence', (_label, fence) => {
      const text = body('repro:', `${fence}text`, LEGACY, renderStaticHint('x'), fence, 'after');

      expect(withoutStaticHint(text)).toBe(text);
    });

    it('resumes stripping once the fence closes', () => {
      const text = body('```', LEGACY, '```', LEGACY);

      expect(withoutStaticHint(text)).toBe(body('```', LEGACY, '```'));
    });

    it('does not close a fence on a shorter fence', () => {
      const text = body('````', '```', LEGACY, '````');

      expect(withoutStaticHint(text)).toBe(text);
    });

    it('does not close a fence on the other fence character', () => {
      const text = body('```', '~~~', LEGACY, '```');

      expect(withoutStaticHint(text)).toBe(text);
    });
  });
});
