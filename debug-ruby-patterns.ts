import { createPatternSource } from './src/security/pattern-source.js';
import { logger } from './src/utils/logger.js';

async function debugRubyPatterns() {
  const performanceRb = `# frozen_string_literal: true
class Performance < ApplicationRecord
  belongs_to :user

  def reviewer_name
   u = User.find_by_id(self.reviewer)
   u.full_name if u.respond_to?("fullname")
  end
end
`;

  console.log("=== Fetching Ruby patterns from production API ===\n");
  
  const patternSource = createPatternSource();
  const patterns = await patternSource.getPatternsByLanguage('ruby');
  
  console.log(`Found ${patterns.length} Ruby patterns\n`);
  console.log("=== Pattern Details ===\n");
  
  patterns.forEach((pattern, i) => {
    console.log(`${i + 1}. ${pattern.id} (${pattern.name})`);
    console.log(`   Type: ${pattern.type}`);
    console.log(`   Severity: ${pattern.severity}`);
    console.log(`   Has AST rules: ${!!pattern.astRules}`);
    console.log(`   Regex count: ${pattern.patterns?.regex?.length || 0}`);
    
    if (pattern.patterns?.regex) {
      pattern.patterns.regex.forEach((regex, j) => {
        console.log(`   Regex ${j + 1}: ${regex.source}`);
        console.log(`   Flags: ${regex.flags}`);
      });
    }
    console.log();
  });
  
  // Now test each pattern individually against performance.rb
  console.log("\n=== Testing Each Pattern Against performance.rb ===\n");
  
  const lines = performanceRb.split('\n');
  
  for (let i = 0; i < patterns.length; i++) {
    const pattern = patterns[i];
    console.log(`Testing pattern ${i + 1}/${patterns.length}: ${pattern.id}`);
    
    if (pattern.patterns?.regex) {
      for (let j = 0; j < pattern.patterns.regex.length; j++) {
        const regex = pattern.patterns.regex[j];
        console.log(`  Regex ${j + 1}: ${regex.source.substring(0, 100)}${regex.source.length > 100 ? '...' : ''}`);
        
        const start = Date.now();
        let matchCount = 0;
        let timedOut = false;
        
        // Set a 2-second timeout
        const timeout = setTimeout(() => {
          timedOut = true;
          console.log(`  ⚠️  TIMEOUT after 2 seconds!`);
        }, 2000);
        
        try {
          regex.lastIndex = 0;
          let match;
          
          while (!timedOut && (match = regex.exec(performanceRb)) !== null) {
            matchCount++;
            
            // Prevent infinite loops on non-global regex
            if (!regex.global) {
              break;
            }
            
            // Safety check - if we've found more than 1000 matches, something is wrong
            if (matchCount > 1000) {
              console.log(`  ⚠️  Too many matches (${matchCount}), breaking`);
              break;
            }
          }
          
          clearTimeout(timeout);
          const duration = Date.now() - start;
          
          if (timedOut) {
            console.log(`  ❌ HUNG - Pattern timed out after 2 seconds`);
            console.log(`  Pattern ID: ${pattern.id}`);
            console.log(`  Pattern regex: ${regex.source}`);
            console.log(`  This is likely the culprit!\n`);
          } else if (duration > 100) {
            console.log(`  ⚠️  SLOW - Took ${duration}ms for ${matchCount} matches`);
          } else {
            console.log(`  ✅ OK - ${duration}ms, ${matchCount} matches`);
          }
        } catch (error: any) {
          clearTimeout(timeout);
          console.log(`  ❌ ERROR: ${error.message}`);
        }
      }
    } else {
      console.log(`  (No regex patterns, AST-only)`);
    }
    console.log();
  }
  
  console.log("=== Pattern Testing Complete ===");
}

debugRubyPatterns().catch(console.error);
