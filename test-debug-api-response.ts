#!/usr/bin/env bun

/**
 * Debug API responses to understand the data structure
 */

import { logger } from './src/utils/logger';

async function debugAPIResponses() {
  console.log('🔍 Debugging RSOLV API Responses\n');
  
  const apiUrl = 'https://api.rsolv.dev/api/v1/patterns';
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer rsolv_enterprise_test_448patterns'
  };

  // Test 1: Language endpoint
  console.log('1️⃣ Testing Language Endpoint: /javascript?format=enhanced');
  try {
    const response = await fetch(`${apiUrl}/javascript?format=enhanced`, { headers });
    const data = await response.json();
    
    console.log('Status:', response.status);
    console.log('Response structure:');
    console.log('  - count:', data.count);
    console.log('  - accessible_tiers:', data.accessible_tiers);
    console.log('  - patterns is array?', Array.isArray(data.patterns));
    
    if (data.patterns && data.patterns.length > 0) {
      console.log('\nFirst pattern structure:');
      const first = data.patterns[0];
      console.log('  - id:', first.id);
      console.log('  - type:', first.type);
      console.log('  - tier:', first.tier || 'not specified');
      console.log('  - patterns field type:', typeof first.patterns);
      console.log('  - patterns is array?', Array.isArray(first.patterns));
      if (first.patterns) {
        console.log('  - patterns[0]:', first.patterns[0]);
      }
    }
  } catch (error) {
    console.error('Error:', error.message);
  }

  // Test 2: Tier endpoint  
  console.log('\n\n2️⃣ Testing Tier Endpoint: /public');
  try {
    const response = await fetch(`${apiUrl}/public`, { headers });
    const data = await response.json();
    
    console.log('Status:', response.status);
    console.log('Response structure:');
    console.log('  - count:', data.count);
    console.log('  - tier:', data.tier);
    console.log('  - patterns type:', typeof data.patterns);
    console.log('  - patterns is array?', Array.isArray(data.patterns));
    
    if (data.patterns) {
      // If it's an object, show keys
      if (typeof data.patterns === 'object' && !Array.isArray(data.patterns)) {
        console.log('  - patterns keys:', Object.keys(data.patterns).slice(0, 5).join(', '), '...');
      }
      // If it's an array, show first item
      if (Array.isArray(data.patterns) && data.patterns.length > 0) {
        console.log('\nFirst pattern:', JSON.stringify(data.patterns[0], null, 2));
      }
    }
  } catch (error) {
    console.error('Error:', error.message);
  }

  // Test 3: Check all language pattern counts
  console.log('\n\n3️⃣ Checking Pattern Counts by Language:');
  const languages = ['javascript', 'python', 'ruby', 'java', 'php', 'elixir'];
  
  for (const lang of languages) {
    try {
      const response = await fetch(`${apiUrl}/${lang}?format=enhanced`, { headers });
      const data = await response.json();
      console.log(`  ${lang}: ${data.count} patterns (tiers: ${data.accessible_tiers?.join(', ') || 'none'})`);
    } catch (error) {
      console.log(`  ${lang}: ERROR`);
    }
  }

  // Test 4: Try different API keys
  console.log('\n\n4️⃣ Testing Different API Keys:');
  const testKeys = [
    { name: 'No key', key: null },
    { name: 'Test key', key: 'test' },
    { name: 'Enterprise key', key: 'rsolv_enterprise_test_448patterns' }
  ];
  
  for (const { name, key } of testKeys) {
    const testHeaders = {
      'Content-Type': 'application/json',
      ...(key && { 'Authorization': `Bearer ${key}` })
    };
    
    try {
      const response = await fetch(`${apiUrl}/javascript?format=enhanced`, { headers: testHeaders });
      const data = await response.json();
      console.log(`  ${name}: ${data.count} patterns, tiers: ${data.accessible_tiers?.join(', ') || 'none'}`);
    } catch (error) {
      console.log(`  ${name}: ERROR`);
    }
  }
}

// Run the debug script
debugAPIResponses().catch(console.error);