/**
 * Test local pattern detection
 * Simulates what the scanner does when it receives the pattern from API
 */

// The pattern as returned by the API
const apiPattern = {
  id: 'js-eval-user-input',
  name: 'Dangerous eval() with User Input',
  type: 'code_injection',
  severity: 'critical',
  description: 'Using eval() with user input can execute arbitrary code',
  regex: '^(?!.*//).*eval\\s*\\(.*?(?:req\\.|request\\.|params\\.|query\\.|body\\.|user|input|data|Code)',
  languages: ['javascript', 'typescript'],
  cweId: 'CWE-94',
  owaspCategory: 'A03:2021',
  recommendation: 'Avoid eval(). Use JSON.parse() for JSON data or find safer alternatives.'
};

// The code from RailsGoat jquery.snippet.js line 737
const testCode = `eval(request.responseText);`;

console.log('=== Testing Pattern Detection ===\n');
console.log('Pattern ID:', apiPattern.id);
console.log('Pattern Type:', apiPattern.type);
console.log('Pattern Regex:', apiPattern.regex);
console.log('\nTest Code:', testCode);

// Convert API regex string to RegExp (simulating pattern-api-client.ts logic)
function convertRegex(regexStr) {
  try {
    // Check if it's in /pattern/flags format
    const match = regexStr.match(/^\/(.*)\/([gimsuvy]*)$/);
    if (match) {
      return new RegExp(match[1], match[2]);
    }
    // Otherwise treat as plain pattern (add 'im' flags as per Elixir pattern)
    return new RegExp(regexStr, 'im');
  } catch (err) {
    console.error('Failed to create regex:', err.message);
    return null;
  }
}

const regex = convertRegex(apiPattern.regex);
console.log('\nConverted RegExp:', regex);

// Test the regex
if (regex) {
  const match = regex.exec(testCode);
  if (match) {
    console.log('\n✓ REGEX MATCHES!');
    console.log('Match:', match[0]);
    console.log('Index:', match.index);
  } else {
    console.log('\n✗ REGEX DOES NOT MATCH');
  }

  // Test with regex.test too
  const testResult = regex.test(testCode);
  console.log('regex.test():', testResult);
} else {
  console.log('\n✗ Failed to create regex');
}

// Test with multi-line code (like in actual file)
const multiLineCode = `
function loadSnippet() {
  var request = new XMLHttpRequest();
  request.open('GET', url, true);
  request.onreadystatechange = function() {
    if (request.readyState === 4 && request.status === 200) {
      eval(request.responseText);
    }
  };
  request.send();
}
`;

console.log('\n=== Testing with multi-line code ===');
const regex2 = convertRegex(apiPattern.regex);
const lines = multiLineCode.split('\n');
let found = false;
lines.forEach((line, i) => {
  if (regex2.test(line)) {
    console.log(`✓ Match on line ${i + 1}: ${line.trim()}`);
    found = true;
  }
});

if (!found) {
  console.log('✗ No matches found in multi-line code');
}
