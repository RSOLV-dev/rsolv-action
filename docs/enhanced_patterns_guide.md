# Enhanced Security Patterns Guide

## Overview

RSOLV's enhanced security patterns provide AST-based vulnerability detection with higher accuracy and fewer false positives compared to traditional regex-based scanning.

## Features

### 1. AST-Based Detection
- Precise code structure matching
- Context-aware analysis
- Reduced false positives

### 2. Confidence Scoring
- Dynamic confidence calculation
- Context-based adjustments
- Prioritization support

### 3. Enhanced Recommendations
- Quick fixes for immediate remediation
- Step-by-step guidance
- Reference links to best practices

### 4. Backward Compatibility
- Works alongside existing regex patterns
- Automatic fallback for non-AST scanners
- Gradual migration path

## Pattern Structure

### Enhanced Pattern Fields

```elixir
%EnhancedPattern{
  # Standard fields (backward compatible)
  id: String.t(),
  name: String.t(),
  description: String.t(),
  type: atom(),
  severity: atom(),
  languages: [String.t()],
  regex: Regex.t() | nil,  # Optional for AST-only patterns
  
  # Enhanced fields
  ast_rules: [             # AST matching rules
    %{
      node_type: atom(),   # e.g., :call_expression, :binary_expression
      properties: map(),   # Node properties to match
      parent_context: atom() | nil,
      child_must_contain: [String.t()] | nil
    }
  ],
  
  context_rules: %{        # Context filtering
    exclude_paths: [String.t()],
    exclude_if_contains: [String.t()],
    require_imports: [String.t()] | nil,
    require_context: [String.t()] | nil
  },
  
  confidence_rules: %{     # Scoring rules
    base_confidence: float(),
    increase_if: [map()],
    decrease_if: [map()]
  },
  
  enhanced_recommendation: %{  # Detailed fixes
    quick_fix: String.t(),
    detailed_steps: [String.t()],
    references: [String.t()]
  }
}
```

## Example: SQL Injection Detection

### Traditional Regex Pattern
```regex
/SELECT.*FROM.*WHERE.*\+\s*\w+/i
```

**Problems:**
- Many false positives
- Misses complex concatenations
- No context awareness

### Enhanced AST Pattern

```elixir
ast_rules: [
  %{
    node_type: :binary_expression,
    properties: %{
      operator: "+",
      left: %{
        type: "Literal",
        value_pattern: ~r/SELECT|INSERT|UPDATE|DELETE/i
      }
    }
  },
  %{
    node_type: :template_literal,
    properties: %{
      contains_pattern: ~r/SELECT|INSERT|UPDATE|DELETE/i,
      has_expressions: true
    }
  }
]
```

**Benefits:**
- Precisely identifies string concatenation with SQL
- Detects template literal interpolation
- Understands code structure

## API Usage

### Get Enhanced Patterns

```bash
# Get enhanced patterns for JavaScript
curl -H "Authorization: Bearer YOUR_API_KEY" \
  https://api.rsolv.dev/api/v1/patterns/enhanced/javascript

# Get all enhanced patterns
curl -H "Authorization: Bearer YOUR_API_KEY" \
  https://api.rsolv.dev/api/v1/patterns/enhanced
```

### Response Format

```json
{
  "patterns": [
    {
      "id": "js-sql-injection-enhanced",
      "name": "SQL Injection via String Operations (Enhanced)",
      "severity": "critical",
      "supports_ast": true,
      "ast_rules": [
        {
          "node_type": "binary_expression",
          "properties": {
            "operator": "+",
            "left": {
              "type": "Literal",
              "value_pattern": "(?:SELECT|INSERT|UPDATE|DELETE)"
            }
          }
        }
      ],
      "context_rules": {
        "exclude_paths": ["test/", "spec/"],
        "exclude_if_contains": ["// safe", "mockQuery"]
      },
      "confidence_rules": {
        "base_confidence": 0.8,
        "increase_if": [
          {
            "condition": "contains_user_input_variable",
            "amount": 0.15
          }
        ]
      },
      "enhanced_recommendation": {
        "quick_fix": "Replace string concatenation with parameterized queries",
        "detailed_steps": [
          "1. Identify the database library you're using",
          "2. Replace concatenation with placeholder syntax",
          "3. Pass user input as parameters"
        ]
      }
    }
  ],
  "format": "enhanced",
  "enhanced_count": 2
}
```

## Integration Guide

### For Scanner Implementations

1. **Check Pattern Support**
   ```javascript
   if (pattern.supports_ast && pattern.ast_rules) {
     // Use AST-based detection
     scanWithAST(code, pattern.ast_rules);
   } else {
     // Fall back to regex
     scanWithRegex(code, pattern.regex);
   }
   ```

2. **Apply Context Rules**
   ```javascript
   function shouldExclude(filePath, fileContent, contextRules) {
     // Check path exclusions
     if (contextRules.exclude_paths?.some(path => 
       filePath.includes(path))) {
       return true;
     }
     
     // Check content exclusions
     if (contextRules.exclude_if_contains?.some(text => 
       fileContent.includes(text))) {
       return true;
     }
     
     return false;
   }
   ```

3. **Calculate Confidence**
   ```javascript
   function calculateConfidence(finding, confidenceRules) {
     let score = confidenceRules.base_confidence;
     
     // Apply increases
     confidenceRules.increase_if?.forEach(rule => {
       if (evaluateCondition(finding, rule.condition)) {
         score += rule.amount;
       }
     });
     
     // Apply decreases
     confidenceRules.decrease_if?.forEach(rule => {
       if (evaluateCondition(finding, rule.condition)) {
         score -= rule.amount;
       }
     });
     
     return Math.max(0, Math.min(1, score));
   }
   ```

## Available Enhanced Patterns

### JavaScript
- **js-sql-injection-enhanced**: SQL injection with AST detection
- **js-missing-error-logging-enhanced**: Missing error logging in catch blocks

### Coming Soon
- Python enhanced patterns
- Java enhanced patterns
- Ruby enhanced patterns

## Feature Flags

Control enhanced pattern behavior with feature flags:

- `patterns.use_enhanced_patterns`: Enable enhanced patterns globally
- `patterns.include_framework_patterns`: Include framework-specific patterns
- `patterns.include_cve_patterns`: Include CVE-based patterns

## Benefits

1. **Higher Accuracy**: AST matching reduces false positives by 70-90%
2. **Better Context**: Understands code structure and relationships
3. **Actionable Fixes**: Detailed remediation guidance
4. **Flexible Scoring**: Confidence adapts to code context
5. **Easy Migration**: Works alongside existing patterns

## Best Practices

1. **Start with High-Value Patterns**: Focus on critical vulnerabilities first
2. **Test in Staging**: Validate enhanced patterns before production use
3. **Monitor Metrics**: Track false positive rates and detection accuracy
4. **Provide Feedback**: Help improve patterns with real-world examples
5. **Use Confidence Scores**: Prioritize findings by confidence level

## Future Enhancements

- Machine learning-based confidence tuning
- Cross-file context analysis
- Auto-fix generation for common patterns
- IDE plugin support
- Real-time scanning APIs