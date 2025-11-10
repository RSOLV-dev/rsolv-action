// Test staging API patterns
const RSOLV_API_KEY = process.env.RSOLV_API_KEY || 'rsolv_test_abcdefg';
const API_URL = 'https://rsolv-staging.com/api/v1/patterns?language=javascript&format=enhanced';

async function testPatterns() {
  console.log('Testing STAGING API patterns...');
  console.log('API URL:', API_URL);
  console.log('Has API Key:', !!RSOLV_API_KEY);
  console.log('API Key prefix:', RSOLV_API_KEY ? RSOLV_API_KEY.substring(0, 15) + '...' : 'none');

  try {
    const response = await fetch(API_URL, {
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': RSOLV_API_KEY
      }
    });

    if (!response.ok) {
      console.error('Failed to fetch patterns:', response.status, response.statusText);
      const text = await response.text();
      console.error('Response:', text);
      return;
    }

    const data = await response.json();
    console.log('\nTotal patterns returned:', data.patterns.length);
    console.log('Metadata:', JSON.stringify(data.metadata, null, 2));

    // Look for eval patterns
    const evalPatterns = data.patterns.filter(p => p.id.includes('eval'));
    console.log('\n=== EVAL PATTERNS ===');
    evalPatterns.forEach(p => {
      console.log(`\nID: ${p.id}`);
      console.log(`Name: ${p.name}`);
      console.log(`Type: ${p.type}`);
      console.log(`Languages: ${p.languages ? p.languages.join(', ') : 'N/A'}`);
    });

    // Check for code_injection type patterns
    const codeInjectionPatterns = data.patterns.filter(p => p.type === 'code_injection');
    console.log('\n=== CODE_INJECTION TYPE PATTERNS ===');
    console.log(`Found ${codeInjectionPatterns.length} code_injection patterns`);
    codeInjectionPatterns.forEach(p => {
      console.log(`- ${p.id}: ${p.name} (languages: ${p.languages ? p.languages.join(', ') : 'N/A'})`);
    });

    // Check if js-eval-user-input is present
    const jsEvalUserInput = data.patterns.find(p => p.id === 'js-eval-user-input');
    console.log('\n=== JS-EVAL-USER-INPUT PATTERN ===');
    if (jsEvalUserInput) {
      console.log('✓ Found js-eval-user-input pattern!');
      console.log('Type:', jsEvalUserInput.type);
      console.log('Severity:', jsEvalUserInput.severity);
      console.log('Regex:', jsEvalUserInput.regex);

      // Test the regex against the RailsGoat code
      const testCode = 'eval(request.responseText);';
      console.log('\nTesting regex against:', testCode);
      if (jsEvalUserInput.regex) {
        const regexStr = jsEvalUserInput.regex;
        console.log('Pattern regex:', regexStr);
        // Try to create a regex from it
        try {
          let regex;
          if (typeof regexStr === 'string') {
            const match = regexStr.match(/^\/(.*)\/([gimsuvy]*)$/);
            if (match) {
              regex = new RegExp(match[1], match[2]);
            } else {
              regex = new RegExp(regexStr);
            }
            const result = regex.test(testCode);
            console.log('Regex test result:', result ? '✓ MATCH' : '✗ NO MATCH');
          }
        } catch (err) {
          console.error('Error testing regex:', err.message);
        }
      }
    } else {
      console.log('✗ js-eval-user-input pattern NOT FOUND');
    }

    // List all pattern IDs for reference
    console.log('\n=== ALL PATTERN IDs ===');
    data.patterns.forEach((p, i) => {
      console.log(`${i + 1}. ${p.id} (${p.type})`);
    });

  } catch (error) {
    console.error('Error:', error.message);
  }
}

testPatterns();
