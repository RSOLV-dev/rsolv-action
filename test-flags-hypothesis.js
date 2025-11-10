/**
 * Test if missing regex flags is the root cause
 */

const regexString = '^(?!.*//).*eval\\s*\\(.*?(?:req\\.|request\\.|params\\.|query\\.|body\\.|user|input|data|Code)';
const testCode = 'eval(request.responseText);';

console.log('=== Testing Regex Flags Hypothesis ===\n');
console.log('Regex pattern:', regexString);
console.log('Test code:', testCode);
console.log('');

// Test WITHOUT flags (current bug)
const regexNoFlags = new RegExp(regexString);
console.log('1. Without flags (CURRENT BUG):');
console.log('   new RegExp(pattern)');
console.log('   Flags:', regexNoFlags.flags || '(none)');
console.log('   Result:', regexNoFlags.test(testCode) ? '✓ MATCH' : '✗ NO MATCH');

// Test WITH 'im' flags (proposed fix)
const regexWithFlags = new RegExp(regexString, 'im');
console.log('\n2. With "im" flags (PROPOSED FIX):');
console.log('   new RegExp(pattern, "im")');
console.log('   Flags:', regexWithFlags.flags);
console.log('   Result:', regexWithFlags.test(testCode) ? '✓ MATCH' : '✗ NO MATCH');

// Test if the negative lookbehind is the issue
console.log('\n=== Analysis ===');
console.log('The pattern starts with ^(?!.*//) which is a negative lookahead');
console.log('It ensures the line doesn\'t start with //');
console.log('');

// Test simpler patterns to isolate issue
const simplePatterns = [
  { desc: 'Just eval match', regex: new RegExp('eval\\s*\\(.*?request\\.') },
  { desc: 'With ^ anchor', regex: new RegExp('^eval\\s*\\(.*?request\\.') },
  { desc: 'With ^ and negative lookahead', regex: new RegExp('^(?!.*//).*eval\\s*\\(.*?request\\.') },
  { desc: 'Full pattern no flags', regex: new RegExp(regexString) },
  { desc: 'Full pattern with im', regex: new RegExp(regexString, 'im') }
];

console.log('Testing component patterns:');
simplePatterns.forEach(({ desc, regex }) => {
  const result = regex.test(testCode);
  console.log(`  ${result ? '✓' : '✗'} ${desc}`);
});

console.log('\n=== Conclusion ===');
console.log('If "Without flags" shows NO MATCH, then missing flags is the root cause.');
console.log('The fix is to add "im" flags when creating RegExp from API string.');
