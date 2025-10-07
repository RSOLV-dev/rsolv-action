import { createPatternSource } from './src/security/pattern-source.js';

const source = createPatternSource();
const patterns = await source.getAllPatterns();

const idCounts = {};
patterns.forEach(p => {
  idCounts[p.id] = (idCounts[p.id] || 0) + 1;
});

const duplicates = Object.entries(idCounts).filter(([id, count]) => count > 1);

console.log('Total patterns:', patterns.length);
console.log('Unique IDs:', Object.keys(idCounts).length);
console.log('Duplicates:', duplicates.length);
if (duplicates.length > 0) {
  console.log('\nDuplicate IDs:');
  duplicates.forEach(([id, count]) => {
    console.log(`  ${id}: appears ${count} times`);
  });
}
