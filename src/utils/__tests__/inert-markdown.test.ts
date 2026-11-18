import { describe, it, expect } from 'vitest';
import { inertInline } from '../inert-markdown.js';

const ZWSP = '​';

describe('inertInline', () => {
  describe('when the text spans lines', () => {
    it.each([
      ['LF', 'safe\n# Heading'],
      ['CRLF', 'safe\r\n# Heading'],
      ['CR', 'safe\r# Heading']
    ])('collapses %s into one line, so no block can start', (_label, text) => {
      expect(inertInline(text, 500)).toBe('safe # Heading');
    });
  });

  describe('when the text carries links and images', () => {
    it('keeps the link text and drops its destination', () => {
      expect(inertInline('see [x](http://evil) now', 500)).toBe('see x now');
    });

    it('keeps the image alt text and drops its source', () => {
      expect(inertInline('![img](http://evil/i.png)', 500)).toBe('img');
    });
  });

  describe('when the text carries bare URLs, which GitHub would autolink', () => {
    it.each([
      ['http', 'go to http://evil.example/login', `go to http:${ZWSP}//evil.example/login`],
      ['https', 'go to https://evil.example/login', `go to https:${ZWSP}//evil.example/login`],
      ['an uppercase scheme', 'HTTPS://EVIL.example', `HTTPS:${ZWSP}//EVIL.example`],
      ['www.', 'go to www.evil.example', `go to www${ZWSP}.evil.example`],
      ['www. after an underscore', '_www.evil.example_', `_www${ZWSP}.evil.example_`]
    ])('breaks %s', (_label, text, inert) => {
      expect(inertInline(text, 500)).toBe(inert);
    });

    it('breaks <https://x> autolink syntax', () => {
      expect(inertInline('<https://x.example>', 500)).toBe(`<${ZWSP}https:${ZWSP}//x.example>`);
    });
  });

  describe('when the text carries a GitHub issue, pull or discussion path', () => {
    it.each([
      ['a full issue URL', 'https://github.com/o/r/issues/1', `https:${ZWSP}//github.com/o/r/issues/${ZWSP}1`],
      ['a scheme-less pull path', 'o/r/pull/12', `o/r/pull/${ZWSP}12`],
      ['a discussion path', 'o/r/discussions/3', `o/r/discussions/${ZWSP}3`]
    ])('breaks %s, so it makes no cross-reference', (_label, text, inert) => {
      expect(inertInline(text, 500)).toBe(inert);
    });
  });

  it('leaves a fullwidth ＠ alone: GitHub does not read it as a mention', () => {
    expect(inertInline('ask ＠octocat', 500)).toBe('ask ＠octocat');
  });

  it('breaks raw HTML', () => {
    expect(inertInline('<img src=x>', 500)).toBe(`<${ZWSP}img src=x>`);
  });

  it('breaks mentions and issue references', () => {
    expect(inertInline('@org/team and #1', 500)).toBe(`@${ZWSP}org/team and #${ZWSP}1`);
  });

  it('breaks closing keywords', () => {
    expect(inertInline('Fixes #1, closed #2, resolves #3', 500))
      .toBe(`F${ZWSP}ixes #${ZWSP}1, c${ZWSP}losed #${ZWSP}2, r${ZWSP}esolves #${ZWSP}3`);
  });

  it('breaks HTML entities, which GitHub decodes before it looks for references', () => {
    expect(inertInline('&amp;#64;', 500)).toBe(`&${ZWSP}amp;#${ZWSP}64;`);
  });

  it('clips long text', () => {
    expect(inertInline('a'.repeat(600), 500)).toBe(`${'a'.repeat(500)}…`);
  });

  it('leaves plain prose alone', () => {
    expect(inertInline('Safe pattern detected: using parameterized query', 500))
      .toBe('Safe pattern detected: using parameterized query');
  });
});
