#!/bin/bash

echo "Final batch of test fixes..."

# Find and fix all Path variable issues
find src -name "*.test.ts" -exec grep -l "Path" {} \; | while read -r file; do
  echo "Fixing path variables in: $file"
  
  # Replace common path variable patterns
  sed -i "s/vi.mock(githubFilesPath/vi.mock('..\/..\/github\/files'/g" "$file"
  sed -i "s/vi.mock(claudeCodePath/vi.mock('..\/adapters\/claude-code'/g" "$file"
  sed -i "s/vi.mock(enhancedClaudeCodePath/vi.mock('..\/adapters\/claude-code-enhanced'/g" "$file"
  sed -i "s/vi.mock(singlePassPath/vi.mock('..\/adapters\/claude-code-single-pass'/g" "$file"
  sed -i "s/vi.mock(gitBasedPath/vi.mock('..\/adapters\/claude-code-git'/g" "$file"
done

# Fix remaining mock() calls
find src -name "*.test.ts" -exec grep -l "\bmock(" {} \; | while read -r file; do
  echo "Fixing mock() in: $file"
  sed -i 's/\bmock(/vi.fn(/g' "$file"
done

# Fix imports
find src -name "*.test.ts" -exec grep -l "@jest/globals" {} \; | while read -r file; do
  echo "Fixing jest imports in: $file"
  sed -i "s/@jest\/globals/vitest/g" "$file"
  sed -i "s/import { jest }/import { vi }/g" "$file"
done

echo "Done!"