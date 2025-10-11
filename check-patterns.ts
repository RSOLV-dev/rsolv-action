import safeRegex from 'safe-regex2';
import { createPatternSource } from './src/security/pattern-source.js';

async function checkPatterns() {
  const source = createPatternSource();
  const patterns = await source.getPatternsByLanguage('ruby');
  
  console.log("=== Ruby Pattern Safety Analysis ===\n");
  
  for (const pattern of patterns) {
    console.log(`Pattern: ${pattern.id}`);
    let allSafe = true;
    
    if (pattern.patterns?.regex) {
      for (let i = 0; i < pattern.patterns.regex.length; i++) {
        const regex = pattern.patterns.regex[i];
        const isSafe = safeRegex(regex, { limit: 25 });
        
        if (!isSafe) {
          allSafe = false;
          console.log(`  ❌ Regex ${i + 1}: UNSAFE - ${regex.source.substring(0, 60)}...`);
        }
      }
    }
    
    if (allSafe && pattern.patterns?.regex?.length > 0) {
      console.log(`  ✅ All ${pattern.patterns.regex.length} patterns are safe`);
    }
  }
}

checkPatterns();
