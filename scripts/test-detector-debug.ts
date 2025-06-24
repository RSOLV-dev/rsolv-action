#!/usr/bin/env bun

import { VulnerabilityType } from '../src/security/types.js';
import { createPatternSource } from '../src/security/pattern-source.js';
import { logger } from '../src/utils/logger.js';

const rubyCode = `# frozen_string_literal: true
class UsersController < ApplicationController
  def update
    message = false
    
    user = User.where("id = '#{params[:user][:id]}'")[0]
    
    if user
      user.update(user_params_without_password)
    end
  end
end`;

async function test() {
  const patternSource = createPatternSource();
  const patterns = await patternSource.getPatternsByLanguage('ruby');
  const sqlPatterns = patterns.filter(p => p.type === VulnerabilityType.SQL_INJECTION);
  
  console.log(`Found ${patterns.length} Ruby patterns`);
  console.log(`Found ${sqlPatterns.length} SQL injection patterns`);
  
  const vulnerabilities: any[] = [];
  const lines = rubyCode.split('\n');
  const seen = new Set<string>();
  
  for (const pattern of sqlPatterns) {
    console.log(`\nTesting pattern: ${pattern.id}`);
    if (pattern.patterns.regex) {
      for (const regex of pattern.patterns.regex) {
        console.log(`  Testing regex: ${regex}`);
        let match;
        regex.lastIndex = 0;
        
        while ((match = regex.exec(rubyCode)) !== null) {
          const lineNumber = rubyCode.substring(0, match.index).split('\n').length;
          const line = lines[lineNumber - 1]?.trim() || '';
          console.log(`    Match found at line ${lineNumber}: "${line}"`);
          
          // Check deduplication
          const key = `${lineNumber}:${pattern.type}`;
          if (seen.has(key)) {
            console.log(`    Skipping duplicate`);
            continue;
          }
          seen.add(key);
          
          vulnerabilities.push({
            type: pattern.type,
            severity: pattern.severity,
            line: lineNumber,
            message: `${pattern.name}: ${pattern.description}`,
            description: pattern.description
          });
          
          if (!regex.global) {
            break;
          }
        }
      }
    }
  }
  
  console.log(`\nTotal vulnerabilities found: ${vulnerabilities.length}`);
  console.log(JSON.stringify(vulnerabilities, null, 2));
}

test().catch(console.error);