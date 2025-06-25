#!/bin/bash

# Fix PHP pattern AST enhancement to use ast_rules instead of rules

echo "Fixing PHP pattern AST enhancement field names..."

for file in lib/rsolv_api/security/patterns/php/*.ex; do
  if grep -q "def ast_enhancement" "$file" && grep -q "rules:" "$file"; then
    echo "Fixing $file"
    
    # Fix the main rules: to ast_rules:
    sed -i 's/^\(\s*\)rules:/\1ast_rules:/' "$file"
    
    # Fix documentation references
    sed -i 's/\[:min_confidence, :rules\]/[:ast_rules, :min_confidence]/' "$file"
    sed -i 's/enhancement\.rules/enhancement.ast_rules/g' "$file"
  fi
done

echo "Done! Fixed all PHP pattern AST enhancement files."