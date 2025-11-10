// Test if the regex matches eval(request.responseText)
const testCode = `eval(request.responseText);`;

// The platform regex from eval_user_input.ex line 66:
// ~r/^(?!.*\/\/).*eval\s*\(.*?(?:req\.|request\.|params\.|query\.|body\.|user|input|data|Code)/im

// JavaScript equivalent:
const regex = /^(?!.*\/\/).*eval\s*\(.*?(?:req\.|request\.|params\.|query\.|body\.|user|input|data|Code)/im;

console.log('Test code:', testCode);
console.log('Regex:', regex);
console.log('Match result:', regex.test(testCode));
console.log('Match details:', testCode.match(regex));

// Test other variations
const tests = [
  'eval(request.responseText);',
  'eval(req.body.code)',
  'const result = eval("2 + " + params.number)',
  'eval(userInput)',
  'eval(data.computation)',
  'eval("static code")',
  '// eval(request.test)',
];

console.log('\n=== Testing multiple cases ===');
tests.forEach(test => {
  const matches = regex.test(test);
  console.log(`${matches ? '✓' : '✗'} ${test}`);
});
