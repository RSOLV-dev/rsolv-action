#!/usr/bin/env bun

/**
 * Test script to measure false positive reduction with enhanced patterns
 * Compares standard regex-only patterns vs enhanced patterns with AST rules
 */

import { readFileSync } from 'fs';
import { join } from 'path';

// Test cases that should NOT be flagged (safe code)
const safeCodeExamples = {
  sqlInjection: [
    // Parameterized queries (safe)
    `db.query("SELECT * FROM users WHERE id = ?", [userId])`,
    `connection.execute('SELECT * FROM products WHERE price > ?', [minPrice])`,
    `db.prepare("INSERT INTO logs (message) VALUES (?)").run(logMessage)`,
    
    // Query builders (safe)
    `knex('users').where('id', userId).select('*')`,
    `User.findOne({ where: { email: userEmail } })`,
    
    // Logging/debugging (not actual queries)
    `console.log("Query would be: SELECT * FROM users WHERE id = " + debugId)`,
    `logger.debug('SQL: DELETE FROM cache WHERE key = ' + cacheKey)`,
    
    // String building for non-DB purposes
    `const message = "User " + userName + " logged in"`,
    `const url = "https://api.example.com/users/" + userId`
  ],
  
  xssDomManipulation: [
    // Escaped/sanitized content (safe)
    `element.innerHTML = DOMPurify.sanitize(userContent)`,
    `div.innerHTML = escapeHtml(comment)`,
    `container.textContent = userInput`, // textContent is safe
    
    // Static content (safe)
    `element.innerHTML = "<strong>Welcome!</strong>"`,
    `div.innerHTML = \`<p>Total: \${calculateTotal()}</p>\``,
    
    // Framework rendering (safe)
    `ReactDOM.render(<div>{userContent}</div>, container)`,
    `this.setState({ content: userInput })` // React escapes by default
  ],
  
  commandInjection: [
    // Array arguments (safe)
    `exec('git', ['checkout', branchName])`,
    `spawn('npm', ['install', packageName])`,
    `execFile('/usr/bin/grep', [pattern, filename])`,
    
    // Escaped/quoted arguments (safe)
    `exec(\`git checkout \${shellEscape(branchName)}\`)`,
    `system("echo " + shellQuote(message))`,
    
    // Static commands (safe)
    `exec("npm run build")`,
    `system("clear")`
  ]
};

// Test cases that SHOULD be flagged (vulnerable code)
const vulnerableCodeExamples = {
  sqlInjection: [
    // Direct concatenation (vulnerable)
    `db.query("SELECT * FROM users WHERE id = " + userId)`,
    `connection.execute('DELETE FROM products WHERE name = "' + productName + '"')`,
    `const sql = "INSERT INTO logs (ip) VALUES ('" + request.ip + "')"`,
    
    // Template literals without parameterization (vulnerable)
    `db.query(\`SELECT * FROM users WHERE email = '\${userEmail}'\`)`,
    `connection.run(\`UPDATE settings SET value = '\${userValue}' WHERE key = 'theme'\`)`
  ],
  
  xssDomManipulation: [
    // Direct innerHTML with user input (vulnerable)
    `element.innerHTML = userComment`,
    `div.innerHTML = "<p>" + searchQuery + "</p>"`,
    `container.innerHTML = \`<div>\${req.query.message}</div>\``,
    
    // jQuery html() with user input (vulnerable)
    `$('#output').html(userInput)`,
    `$('.comments').html('<div>' + comment + '</div>')`
  ],
  
  commandInjection: [
    // String concatenation in shell commands (vulnerable)
    `exec("git checkout " + branchName)`,
    `system("rm -rf /tmp/" + userPath)`,
    `shell_exec('grep "' + pattern + '" /var/log/app.log')`,
    
    // Template literals in shell commands (vulnerable)
    `exec(\`docker run \${imageName}\`)`,
    `system(\`tar -xzf \${uploadedFile}\`)`
  ]
};

async function testPatternAgainstCode(pattern: any, code: string, isEnhanced: boolean): Promise<boolean> {
  // For standard patterns, just test regex
  if (!isEnhanced) {
    const regexPatterns = pattern.regex_patterns || [];
    for (const regexStr of regexPatterns) {
      const regex = new RegExp(regexStr, 'i');
      if (regex.test(code)) {
        return true; // Flagged as vulnerable
      }
    }
    return false;
  }
  
  // For enhanced patterns, we would need AST analysis
  // This is a simplified simulation - in reality, the RSOLV Action would do full AST analysis
  const astRules = pattern.ast_rules || {};
  const contextRules = pattern.context_rules || {};
  
  // Simulate basic AST-based filtering
  // Check if code is in test file (should be excluded)
  if (contextRules.exclude_paths && code.includes('test') || code.includes('spec')) {
    return false;
  }
  
  // Check for parameterized query markers
  if (contextRules.exclude_if_parameterized && (code.includes('?') || code.includes('$1'))) {
    return false;
  }
  
  // Check for escaping functions
  if (contextRules.safe_if_wrapped) {
    for (const safeFunc of contextRules.safe_if_wrapped) {
      if (code.includes(safeFunc)) {
        return false;
      }
    }
  }
  
  // If we get here, check regex
  const regexPatterns = pattern.regex_patterns || [];
  for (const regexStr of regexPatterns) {
    const regex = new RegExp(regexStr, 'i');
    if (regex.test(code)) {
      return true; // Flagged as vulnerable
    }
  }
  
  return false;
}

async function measureFalsePositives() {
  console.log("🔍 Testing False Positive Reduction with Enhanced Patterns\n");
  
  // Fetch patterns from staging API
  const standardResponse = await fetch('https://api.rsolv-staging.com/api/v1/patterns?language=javascript&format=standard');
  const enhancedResponse = await fetch('https://api.rsolv-staging.com/api/v1/patterns?language=javascript&format=enhanced');
  
  const standardData = await standardResponse.json();
  const enhancedData = await enhancedResponse.json();
  
  console.log(`📊 Testing ${standardData.patterns.length} patterns\n`);
  
  const results: any = {};
  
  // Test each pattern type
  for (const patternType of ['sqlInjection', 'xssDomManipulation', 'commandInjection']) {
    const pattern = standardData.patterns.find((p: any) => 
      p.type === patternType.replace(/([A-Z])/g, '_$1').toLowerCase()
    );
    
    if (!pattern) continue;
    
    const enhancedPattern = enhancedData.patterns.find((p: any) => p.id === pattern.id);
    
    results[patternType] = {
      standard: { falsePositives: 0, truePositives: 0, falseNegatives: 0 },
      enhanced: { falsePositives: 0, truePositives: 0, falseNegatives: 0 }
    };
    
    // Test safe code (should NOT be flagged)
    const safeExamples = safeCodeExamples[patternType as keyof typeof safeCodeExamples] || [];
    for (const code of safeExamples) {
      if (await testPatternAgainstCode(pattern, code, false)) {
        results[patternType].standard.falsePositives++;
      }
      if (await testPatternAgainstCode(enhancedPattern, code, true)) {
        results[patternType].enhanced.falsePositives++;
      }
    }
    
    // Test vulnerable code (SHOULD be flagged)
    const vulnExamples = vulnerableCodeExamples[patternType as keyof typeof vulnerableCodeExamples] || [];
    for (const code of vulnExamples) {
      if (await testPatternAgainstCode(pattern, code, false)) {
        results[patternType].standard.truePositives++;
      } else {
        results[patternType].standard.falseNegatives++;
      }
      
      if (await testPatternAgainstCode(enhancedPattern, code, true)) {
        results[patternType].enhanced.truePositives++;
      } else {
        results[patternType].enhanced.falseNegatives++;
      }
    }
  }
  
  // Display results
  console.log("📈 Results:\n");
  
  for (const [patternType, data] of Object.entries(results)) {
    const standardFPRate = data.standard.falsePositives / 
      (safeCodeExamples[patternType as keyof typeof safeCodeExamples]?.length || 1) * 100;
    const enhancedFPRate = data.enhanced.falsePositives / 
      (safeCodeExamples[patternType as keyof typeof safeCodeExamples]?.length || 1) * 100;
    const reduction = ((standardFPRate - enhancedFPRate) / standardFPRate * 100).toFixed(1);
    
    console.log(`${patternType}:`);
    console.log(`  Standard Format:`);
    console.log(`    - False Positives: ${data.standard.falsePositives}/${safeCodeExamples[patternType as keyof typeof safeCodeExamples]?.length} (${standardFPRate.toFixed(1)}%)`);
    console.log(`    - True Positives: ${data.standard.truePositives}/${vulnerableCodeExamples[patternType as keyof typeof vulnerableCodeExamples]?.length}`);
    console.log(`  Enhanced Format:`);
    console.log(`    - False Positives: ${data.enhanced.falsePositives}/${safeCodeExamples[patternType as keyof typeof safeCodeExamples]?.length} (${enhancedFPRate.toFixed(1)}%)`);
    console.log(`    - True Positives: ${data.enhanced.truePositives}/${vulnerableCodeExamples[patternType as keyof typeof vulnerableCodeExamples]?.length}`);
    console.log(`  📉 False Positive Reduction: ${reduction}%\n`);
  }
}

// Run the test
measureFalsePositives().catch(console.error);