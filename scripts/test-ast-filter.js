const patterns = [
  { id: 'test1', astRules: undefined },
  { id: 'test2', astRules: null },  
  { id: 'test3', astRules: {} },
  { id: 'test4' }
];

console.log('AST patterns:', patterns.filter(p => p.astRules));
console.log('Regex patterns:', patterns.filter(p => !p.astRules));