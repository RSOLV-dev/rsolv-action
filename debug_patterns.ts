#!/usr/bin/env bun

// Debug script to see what patterns we're getting

async function debugPatterns() {
  const response = await fetch('https://api.rsolv-staging.com/api/v1/patterns?language=javascript&format=enhanced');
  const data = await response.json();
  
  console.log("Patterns received:");
  for (const pattern of data.patterns) {
    console.log(`\n${pattern.id} (${pattern.type}):`);
    console.log("  regex_patterns:", pattern.regex_patterns);
    console.log("  ast_rules:", JSON.stringify(pattern.ast_rules, null, 2));
    console.log("  context_rules:", JSON.stringify(pattern.context_rules, null, 2));
  }
}

debugPatterns().catch(console.error);