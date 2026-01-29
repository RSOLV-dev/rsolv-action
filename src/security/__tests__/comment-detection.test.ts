/**
 * TDD test: Verify SecurityDetectorV2 skips code inside comments.
 *
 * Bug: The regex-based scanner scans every line individually without checking
 * whether it's inside a block comment or is a single-line comment. This causes
 * false positives from commented-out code.
 */

import { describe, it, expect } from 'vitest';
import { SecurityDetectorV2 } from '../detector-v2.js';
import { LocalPatternSource } from '../pattern-source.js';

describe('SecurityDetectorV2 comment block awareness', () => {
  it('should not flag SQL injection patterns inside block comments', async () => {
    const code = `function doSomething() {
  /*
   * Old code:
   * var query = "SELECT * FROM users WHERE id = '" + userId + "'";
   * db.query(query);
   */
  return db.query('SELECT * FROM users WHERE id = $1', [userId]);
}`;
    const detector = new SecurityDetectorV2(new LocalPatternSource());
    const results = await detector.detect(code, 'javascript', 'test.js');
    // The parameterized query on line 7 is safe; nothing inside the comment should be flagged
    expect(results).toHaveLength(0);
  });

  it('should not flag patterns inside single-line comments', async () => {
    const code = `function query() {
  // var q = "SELECT * FROM users WHERE id = '" + input + "'";
  return db.query('SELECT * FROM users WHERE id = $1', [input]);
}`;
    const detector = new SecurityDetectorV2(new LocalPatternSource());
    const results = await detector.detect(code, 'javascript', 'test.js');
    expect(results).toHaveLength(0);
  });

  it('should still flag vulnerable code outside comments', async () => {
    const code = `function query(userId) {
  /* This is a comment */
  var q = "SELECT * FROM users WHERE id = '" + userId + "'";
  db.query(q);
}`;
    const detector = new SecurityDetectorV2(new LocalPatternSource());
    const results = await detector.detect(code, 'javascript', 'test.js');
    expect(results.length).toBeGreaterThan(0);
  });

  it('should handle mixed comments and code correctly', async () => {
    const code = `function process(input) {
  // eval(input); // old approach
  /*
   * Also tried: eval(input);
   */
  const safe = sanitize(input);
  return safe;
}`;
    const detector = new SecurityDetectorV2(new LocalPatternSource());
    const results = await detector.detect(code, 'javascript', 'test.js');
    // eval calls are only in comments, so nothing should be flagged
    expect(results).toHaveLength(0);
  });

  it('should handle inline block comments on same line as code', async () => {
    const code = `function query(userId) {
  var q = "SELECT * FROM users WHERE id = '" + userId + "'"; /* vulnerable */
  db.query(q);
}`;
    const detector = new SecurityDetectorV2(new LocalPatternSource());
    const results = await detector.detect(code, 'javascript', 'test.js');
    // The vulnerable code IS on the line (not wholly inside comment), so it should be flagged
    expect(results.length).toBeGreaterThan(0);
  });

  it('should handle nodegoat-style block comment with crypto code', async () => {
    // Real-world case from nodegoat profile-dao.js
    const code = `function processProfile(userId, input) {
  /*
   * NOTE: This is intentionally vulnerable for training purposes
   * var cipher = crypto.createCipher('aes256', key);
   * var encrypted = cipher.update(input, 'utf8', 'hex');
   * var query = "SELECT * FROM users WHERE id = '" + userId + "'";
   */
  return db.query('SELECT * FROM users WHERE id = $1', [userId]);
}`;
    const detector = new SecurityDetectorV2(new LocalPatternSource());
    const results = await detector.detect(code, 'javascript', 'test.js');
    expect(results).toHaveLength(0);
  });
});
