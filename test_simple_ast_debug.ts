#!/usr/bin/env bun

/**
 * Simple AST Debug Test - Works with running server
 * Tests individual components to isolate the issue
 */

const API_KEY = 'rsolv_test_abc123';

async function testPatternAPI() {
  console.log('🔍 Testing Pattern API directly...');
  
  try {
    const response = await fetch('http://localhost:4000/api/v1/patterns?language=python&format=enhanced');
    console.log(`Status: ${response.status}`);
    
    if (response.ok) {
      const data = await response.json();
      console.log(`Found ${data.patterns?.length || 0} patterns`);
      
      // Look for SQL patterns
      const sqlPatterns = data.patterns?.filter((p: any) => 
        p.id.includes('sql') || p.title?.toLowerCase().includes('sql')
      ) || [];
      
      console.log(`SQL patterns: ${sqlPatterns.length}`);
      sqlPatterns.slice(0, 3).forEach((p: any) => {
        console.log(`  - ${p.id}: ${p.title}`);
        console.log(`    AST rules: ${p.ast_rules ? Object.keys(p.ast_rules).length : 0}`);
        console.log(`    Context rules: ${p.context_rules ? Object.keys(p.context_rules).length : 0}`);
      });
    } else {
      const text = await response.text();
      console.log(`Error: ${text}`);
    }
  } catch (error) {
    console.log(`Error: ${error}`);
  }
}

async function testHealthAPI() {
  console.log('\n🏥 Testing Health API...');
  
  try {
    const response = await fetch('http://localhost:4000/health');
    console.log(`Status: ${response.status}`);
    
    if (response.ok) {
      const text = await response.text();
      console.log(`Response: ${text}`);
    }
  } catch (error) {
    console.log(`Error: ${error}`);
  }
}

async function testMinimalAST() {
  console.log('\n🧪 Testing minimal AST request...');
  
  try {
    const response = await fetch('http://localhost:4000/api/v1/ast/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
      },
      body: JSON.stringify({
        files: [],
        options: {
          patternFormat: 'enhanced'
        }
      })
    });
    
    console.log(`Status: ${response.status}`);
    const text = await response.text();
    console.log(`Response: ${text.substring(0, 200)}...`);
    
  } catch (error) {
    console.log(`Error: ${error}`);
  }
}

async function main() {
  console.log('🚀 Simple AST Debug Test');
  console.log('='.repeat(30));
  
  await testHealthAPI();
  await testPatternAPI();
  await testMinimalAST();
  
  console.log('\n✅ Simple test completed');
}

main().catch(console.error);