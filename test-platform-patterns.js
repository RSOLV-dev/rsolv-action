// Quick test to check what patterns the platform API returns

const RSOLV_API_KEY = process.env.RSOLV_API_KEY;
const API_URL = 'https://api.rsolv.dev/api/v1/patterns?language=javascript&format=enhanced';

async function testPatterns() {
  console.log('Testing platform API patterns...');
  console.log('API URL:', API_URL);
  console.log('Has API Key:', !!RSOLV_API_KEY);

  const response = await fetch(API_URL, {
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': RSOLV_API_KEY || ''
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
  console.log('Metadata:', data.metadata);

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
    console.log(`- ${p.id}: ${p.name}`);
  });

  // Check if js-eval-user-input is present
  const jsEvalUserInput = data.patterns.find(p => p.id === 'js-eval-user-input');
  console.log('\n=== JS-EVAL-USER-INPUT PATTERN ===');
  if (jsEvalUserInput) {
    console.log('✓ Found js-eval-user-input pattern!');
    console.log('Type:', jsEvalUserInput.type);
    console.log('Severity:', jsEvalUserInput.severity);
    console.log('Regex:', jsEvalUserInput.regex);
  } else {
    console.log('✗ js-eval-user-input pattern NOT FOUND');
  }
}

testPatterns().catch(console.error);
