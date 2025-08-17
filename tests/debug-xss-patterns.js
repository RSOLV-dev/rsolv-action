// Debug script to test XSS patterns
const patterns = [
  {
    name: 'Direct HTML injection via innerHTML',
    regex: /innerHTML\s*=\s*[^;]+(?:user|req\.|params|query)/gi
  },
  {
    name: 'Document.write with user input or concatenation',
    regex: /document\.write(?:ln)?\s*\([^)]*(?:user|req\.|params|query|\+|`)/gi
  },
  {
    name: 'OuterHTML injection',
    regex: /outerHTML\s*=\s*[^;]+(?:user|req\.|params|query)/gi
  },
  {
    name: 'jQuery html() with user input',
    regex: /\$\([^)]+\)\.html\s*\([^)]*(?:user|req\.|params|query)/gi
  }
];

const examples = [
  { code: 'element.innerHTML = userInput;', description: 'Direct innerHTML assignment' },
  { code: 'document.write(userInput);', description: 'document.write with user input' },
  { code: 'document.write("<script>" + userInput + "</script>");', description: 'document.write with concatenation' },
  { code: 'element.outerHTML = req.body.content;', description: 'outerHTML assignment' },
  { code: 'document.writeln(params.text);', description: 'document.writeln with user input' },
  { code: '$(element).html(req.query.html);', description: 'jQuery html() with user input' }
];

console.log('Testing XSS patterns:');
console.log('=====================\n');

for (const example of examples) {
  console.log(`Testing: ${example.description}`);
  console.log(`Code: ${example.code}`);
  
  let matched = false;
  let matchedPattern = null;
  
  for (const pattern of patterns) {
    if (pattern.regex.test(example.code)) {
      matched = true;
      matchedPattern = pattern.name;
      break;
    }
  }
  
  if (matched) {
    console.log(`✓ MATCHED by: ${matchedPattern}`);
  } else {
    console.log(`✗ NO MATCH`);
  }
  console.log('');
}