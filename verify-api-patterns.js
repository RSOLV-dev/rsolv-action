#!/usr/bin/env node
/**
 * Verify API Pattern Response Test
 *
 * This script tests the staging API to determine why js-eval-user-input
 * pattern is not being detected in RailsGoat scan.
 *
 * Usage:
 *   RSOLV_API_KEY=your_key_here node verify-api-patterns.js
 */

const API_KEY = process.env.RSOLV_API_KEY;
const STAGING_URL = 'https://rsolv-staging.com/api/v1/patterns';
const PROD_URL = 'https://api.rsolv.dev/api/v1/patterns';

async function testAPI(baseUrl, name) {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`Testing: ${name}`);
  console.log(`URL: ${baseUrl}`);
  console.log(`${'='.repeat(60)}\n`);

  if (!API_KEY) {
    console.error('❌ ERROR: RSOLV_API_KEY environment variable not set');
    console.log('\nUsage: RSOLV_API_KEY=your_key node verify-api-patterns.js');
    return null;
  }

  const url = `${baseUrl}?language=javascript&format=enhanced`;
  console.log(`Fetching: ${url}`);
  console.log(`API Key: ${API_KEY.substring(0, 15)}...`);

  try {
    const response = await fetch(url, {
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': API_KEY
      }
    });

    console.log(`\nResponse Status: ${response.status} ${response.statusText}`);

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`\n❌ API Error Response:`);
      console.error(errorText);
      return null;
    }

    const data = await response.json();
    console.log(`\n✓ Success! Retrieved patterns`);
    console.log(`\nMetadata:`, JSON.stringify(data.metadata, null, 2));
    console.log(`Total patterns: ${data.patterns.length}`);

    return data;
  } catch (error) {
    console.error(`\n❌ Request Error:`, error.message);
    return null;
  }
}

async function analyzePatterns(data, environmentName) {
  if (!data) {
    console.log(`\n⚠️  Skipping analysis for ${environmentName} (no data)\n`);
    return;
  }

  console.log(`\n${'─'.repeat(60)}`);
  console.log(`Analyzing ${environmentName} Patterns`);
  console.log(`${'─'.repeat(60)}\n`);

  // Check for js-eval-user-input specifically
  const jsEvalUserInput = data.patterns.find(p => p.id === 'js-eval-user-input');

  console.log(`\n### JS-EVAL-USER-INPUT PATTERN ###`);
  if (jsEvalUserInput) {
    console.log(`✓ FOUND: js-eval-user-input pattern`);
    console.log(`\nPattern Details:`);
    console.log(`  ID: ${jsEvalUserInput.id}`);
    console.log(`  Name: ${jsEvalUserInput.name}`);
    console.log(`  Type: ${jsEvalUserInput.type}`);
    console.log(`  Severity: ${jsEvalUserInput.severity}`);
    console.log(`  CWE: ${jsEvalUserInput.cweId || jsEvalUserInput.cwe_id}`);
    console.log(`  OWASP: ${jsEvalUserInput.owaspCategory || jsEvalUserInput.owasp_category}`);
    console.log(`  Languages: ${jsEvalUserInput.languages ? jsEvalUserInput.languages.join(', ') : 'N/A'}`);

    if (jsEvalUserInput.regex) {
      console.log(`  Regex: ${jsEvalUserInput.regex}`);

      // Test the regex against RailsGoat code
      const testCode = 'eval(request.responseText);';
      console.log(`\n  Testing regex against: "${testCode}"`);

      try {
        let regex;
        if (typeof jsEvalUserInput.regex === 'string') {
          const match = jsEvalUserInput.regex.match(/^\/(.*)\/([gimsuvy]*)$/);
          if (match) {
            regex = new RegExp(match[1], match[2]);
          } else {
            regex = new RegExp(jsEvalUserInput.regex, 'im');
          }

          const testResult = regex.test(testCode);
          if (testResult) {
            console.log(`  ✓ REGEX MATCHES: Pattern should detect the RailsGoat eval()`);
          } else {
            console.log(`  ✗ REGEX DOES NOT MATCH: Pattern will not detect the vulnerability`);
          }
        } else {
          console.log(`  ⚠️  Regex is not a string:`, typeof jsEvalUserInput.regex);
        }
      } catch (err) {
        console.error(`  ✗ Error testing regex:`, err.message);
      }
    } else {
      console.log(`  ⚠️  No regex field found in pattern`);
    }

    // Check for AST rules if in enhanced format
    if (jsEvalUserInput.astRules || jsEvalUserInput.ast_rules) {
      console.log(`  ✓ Has AST rules (enhanced format)`);
    }
  } else {
    console.log(`✗ NOT FOUND: js-eval-user-input pattern is MISSING from API response`);
    console.log(`\nThis explains why the RailsGoat eval() was not detected!`);
  }

  // List all CODE_INJECTION type patterns
  const codeInjectionPatterns = data.patterns.filter(p =>
    p.type === 'code_injection' || p.type === 'CODE_INJECTION'
  );

  console.log(`\n### CODE_INJECTION TYPE PATTERNS ###`);
  console.log(`Found ${codeInjectionPatterns.length} code_injection patterns:`);
  if (codeInjectionPatterns.length > 0) {
    codeInjectionPatterns.forEach(p => {
      const langs = p.languages ? ` (${p.languages.join(', ')})` : '';
      console.log(`  - ${p.id}: ${p.name}${langs}`);
    });
  } else {
    console.log(`  ⚠️  No code_injection type patterns found`);
    console.log(`  This suggests the API might not be returning the new type,`);
    console.log(`  or staging hasn't been deployed with PR #113 changes.`);
  }

  // Look for patterns with 'eval' in the ID
  const evalPatterns = data.patterns.filter(p => p.id.includes('eval'));
  console.log(`\n### EVAL-RELATED PATTERNS ###`);
  console.log(`Found ${evalPatterns.length} patterns with 'eval' in ID:`);
  evalPatterns.forEach(p => {
    console.log(`  - ${p.id}: ${p.name} (type: ${p.type})`);
  });

  // Check for RCE type (old type before PR #113)
  const rcePatterns = data.patterns.filter(p =>
    p.type === 'rce' || p.type === 'RCE'
  );
  if (rcePatterns.length > 0) {
    console.log(`\n⚠️  FOUND RCE TYPE PATTERNS (OLD TYPE):`);
    rcePatterns.forEach(p => {
      console.log(`  - ${p.id}: ${p.name}`);
    });
    console.log(`\n  This indicates staging is serving OLD patterns from before PR #113!`);
    console.log(`  PR #113 changed :rce → :code_injection on Nov 9, 2025`);
  }

  // Summary of all pattern types
  const typeCount = {};
  data.patterns.forEach(p => {
    typeCount[p.type] = (typeCount[p.type] || 0) + 1;
  });

  console.log(`\n### PATTERN TYPE DISTRIBUTION ###`);
  console.log(`Total unique types: ${Object.keys(typeCount).length}`);
  Object.entries(typeCount)
    .sort((a, b) => b[1] - a[1])
    .forEach(([type, count]) => {
      console.log(`  ${type}: ${count}`);
    });

  // List all pattern IDs for reference
  console.log(`\n### ALL PATTERN IDs (${data.patterns.length} total) ###`);
  data.patterns
    .sort((a, b) => a.id.localeCompare(b.id))
    .forEach((p, i) => {
      console.log(`  ${String(i + 1).padStart(2)}. ${p.id.padEnd(40)} (${p.type})`);
    });
}

async function main() {
  console.log('╔' + '═'.repeat(60) + '╗');
  console.log('║' + ' RSOLV API Pattern Verification Test'.padEnd(60) + '║');
  console.log('╚' + '═'.repeat(60) + '╝');

  // Test staging (where RailsGoat test ran)
  const stagingData = await testAPI(STAGING_URL, 'STAGING Environment');
  await analyzePatterns(stagingData, 'STAGING');

  // Test production for comparison
  const prodData = await testAPI(PROD_URL, 'PRODUCTION Environment');
  await analyzePatterns(prodData, 'PRODUCTION');

  // Final diagnosis
  console.log(`\n${'═'.repeat(60)}`);
  console.log(`DIAGNOSIS & RECOMMENDATIONS`);
  console.log(`${'═'.repeat(60)}\n`);

  if (!stagingData) {
    console.log(`❌ Unable to diagnose - staging API request failed`);
    console.log(`   Check API key and network connectivity\n`);
    return;
  }

  const stagingHasPattern = stagingData.patterns.some(p => p.id === 'js-eval-user-input');
  const stagingHasCodeInjection = stagingData.patterns.some(p => p.type === 'code_injection');
  const stagingHasRCE = stagingData.patterns.some(p => p.type === 'rce');

  if (!stagingHasPattern) {
    console.log(`ROOT CAUSE CONFIRMED:`);
    console.log(`  ✗ js-eval-user-input pattern is MISSING from staging API\n`);

    if (stagingHasRCE) {
      console.log(`SPECIFIC ISSUE:`);
      console.log(`  ⚠️  Staging is serving patterns with OLD :rce type`);
      console.log(`  ⚠️  PR #113 changed :rce → :code_injection on Nov 9, 2025`);
      console.log(`  ⚠️  Staging environment was NOT redeployed after merge\n`);

      console.log(`RECOMMENDED FIX:`);
      console.log(`  1. Deploy staging with latest main branch`);
      console.log(`  2. Or clear pattern cache on staging`);
      console.log(`  3. Re-run RailsGoat E2E validation\n`);
    } else if (!stagingHasCodeInjection) {
      console.log(`SPECIFIC ISSUE:`);
      console.log(`  ⚠️  No code_injection type patterns found at all`);
      console.log(`  ⚠️  Pattern type might be filtered or not loaded\n`);

      console.log(`RECOMMENDED FIX:`);
      console.log(`  1. Check Pattern Server loading logic`);
      console.log(`  2. Verify pattern files are accessible`);
      console.log(`  3. Check for pattern type filtering\n`);
    } else {
      console.log(`SPECIFIC ISSUE:`);
      console.log(`  ⚠️  code_injection type exists but js-eval-user-input missing`);
      console.log(`  ⚠️  Pattern registration or loading issue\n`);

      console.log(`RECOMMENDED FIX:`);
      console.log(`  1. Verify EvalUserInput module is compiled`);
      console.log(`  2. Check javascript.ex includes eval_user_input()`);
      console.log(`  3. Restart Pattern Server GenServer\n`);
    }
  } else if (stagingHasPattern) {
    console.log(`✓ js-eval-user-input pattern IS present in staging API\n`);

    console.log(`SECONDARY INVESTIGATION NEEDED:`);
    console.log(`  The pattern exists but wasn't detected. Possible causes:`);
    console.log(`  1. RSOLV-action not using the pattern correctly`);
    console.log(`  2. Regex serialization/deserialization issue`);
    console.log(`  3. Worker thread detection failure`);
    console.log(`  4. Pattern type mapping issue in action\n`);

    console.log(`RECOMMENDED NEXT STEPS:`);
    console.log(`  1. Test pattern detection locally with test-eval.js`);
    console.log(`  2. Check action logs for pattern processing errors`);
    console.log(`  3. Verify regex reconstruction in pattern-api-client.ts\n`);
  }

  console.log(`${'═'.repeat(60)}\n`);
}

// Run the test
main().catch(error => {
  console.error('\n❌ FATAL ERROR:', error);
  process.exit(1);
});
