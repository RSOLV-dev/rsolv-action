# Pattern Migration Guide: Regex to AST

## Overview

This guide helps you migrate existing regex-based security patterns to enhanced AST-based patterns for improved accuracy and reduced false positives.

## Migration Strategy

### Phase 1: Identify High-Value Patterns
Start with patterns that have:
- High false positive rates
- Complex regex expressions
- Critical security impact
- Frequent use in scans

### Phase 2: Create Enhanced Versions
1. Keep the original regex for backward compatibility
2. Add AST rules for precise detection
3. Include context rules to filter false positives
4. Add confidence scoring logic

### Phase 3: Test and Validate
1. Run both patterns in parallel
2. Compare detection results
3. Measure false positive reduction
4. Validate all test cases still pass

### Phase 4: Gradual Rollout
1. Enable via feature flags
2. Monitor performance metrics
3. Gather user feedback
4. Adjust confidence rules as needed

## Example Migration: SQL Injection

### Original Regex Pattern

```elixir
def sql_injection_concat do
  %Pattern{
    id: "js-sql-injection-concat",
    regex: ~r/(?:const|let|var)\s+\w+\s*=\s*["'`](?:SELECT|INSERT|UPDATE|DELETE).*["'`]\s*\+\s*\w+/i,
    # ... other fields
  }
end
```

**Issues:**
- Matches commented code
- False positives in test files
- Misses complex concatenations
- No understanding of code flow

### Enhanced AST Pattern

```elixir
def sql_injection_enhanced do
  %EnhancedPattern{
    id: "js-sql-injection-enhanced",
    # Keep regex for compatibility
    regex: ~r/(?:const|let|var)\s+\w+\s*=\s*["'`](?:SELECT|INSERT|UPDATE|DELETE).*["'`]\s*\+\s*\w+/i,
    
    # Add precise AST rules
    ast_rules: [
      %{
        node_type: :binary_expression,
        properties: %{
          operator: "+",
          left: %{
            type: "Literal",
            value_pattern: ~r/(?:SELECT|INSERT|UPDATE|DELETE)/i
          }
        }
      },
      %{
        node_type: :template_literal,
        properties: %{
          contains_pattern: ~r/(?:SELECT|INSERT|UPDATE|DELETE)/i,
          has_expressions: true
        }
      },
      %{
        node_type: :call_expression,
        properties: %{
          callee: %{
            object_pattern: ~r/^(db|database|conn)$/,
            property_pattern: ~r/^(query|exec)$/
          },
          arguments: %{
            first_contains_concat: true
          }
        }
      }
    ],
    
    # Add context filtering
    context_rules: %{
      exclude_paths: ["test/", "spec/", "__tests__/", "migrations/"],
      exclude_if_contains: ["mockQuery", "// safe", "/* test */"]
    },
    
    # Add dynamic scoring
    confidence_rules: %{
      base_confidence: 0.8,
      increase_if: [
        %{
          condition: "contains_user_input_variable",
          description: "Variable from req/params/body",
          amount: 0.15
        }
      ],
      decrease_if: [
        %{
          condition: "has_validation_nearby",
          description: "Input validation detected",
          amount: 0.2
        }
      ]
    }
  }
end
```

## Common AST Node Types

### JavaScript/TypeScript

| Node Type | Description | Common Use Cases |
|-----------|-------------|------------------|
| `call_expression` | Function calls | API misuse, dangerous functions |
| `member_expression` | Property access | DOM manipulation, unsafe properties |
| `binary_expression` | Binary operations | String concatenation, comparisons |
| `template_literal` | Template strings | Interpolation vulnerabilities |
| `assignment` | Variable assignments | Hardcoded secrets, unsafe values |
| `try_statement` | Try-catch blocks | Error handling issues |
| `if_statement` | Conditional logic | Security checks, validation |
| `import_declaration` | Import statements | Vulnerable dependencies |

### Property Matching Patterns

```elixir
# Match specific function names
%{
  callee: %{
    name: "eval"  # matches eval(...)
  }
}

# Match method calls
%{
  callee: %{
    object: "document",
    property: "write"  # matches document.write(...)
  }
}

# Match with patterns
%{
  callee: %{
    object_pattern: ~r/^(fs|filesystem)$/,
    property_pattern: ~r/^(read|write)/  # matches fs.readFile, filesystem.writeSync
  }
}

# Match nested properties
%{
  arguments: %{
    first: %{
      type: "Literal",
      value_pattern: ~r/password/i
    }
  }
}
```

## Context Rule Patterns

### Path Exclusions
```elixir
exclude_paths: [
  "test/",
  "tests/",
  "spec/",
  "__tests__/",
  "node_modules/",
  "vendor/",
  "third_party/",
  ".git/",
  "migrations/",
  "seeds/",
  "fixtures/"
]
```

### Content Exclusions
```elixir
exclude_if_contains: [
  "// @security-disable",
  "/* eslint-disable security */",
  "// safe: reviewed by security team",
  "// intentionally vulnerable for testing",
  "#pragma warning disable",
  "# rubocop:disable"
]
```

### Required Context
```elixir
require_imports: [
  "express",  # Only flag in Express apps
  "mysql2"    # Only flag if using MySQL
]

require_context: [
  "async function",  # Only in async functions
  "class Component"  # Only in React components
]
```

## Confidence Scoring Examples

### High Confidence Indicators
- User input variables (req.*, params.*, body.*)
- Sensitive operations (auth, payment, admin)
- Production code paths
- Missing security controls

### Low Confidence Indicators
- Test/example code
- Validated/sanitized input
- Safe coding patterns nearby
- Developer comments explaining safety

### Example Scoring Logic

```elixir
confidence_rules: %{
  base_confidence: 0.7,
  
  increase_if: [
    %{
      condition: "in_route_handler",
      description: "Inside Express route handler",
      amount: 0.2
    },
    %{
      condition: "uses_user_input",
      description: "Directly uses req.params or req.body",
      amount: 0.15
    },
    %{
      condition: "no_validation_found",
      description: "No input validation in function",
      amount: 0.1
    }
  ],
  
  decrease_if: [
    %{
      condition: "has_security_comment",
      description: "Comment indicates security review",
      amount: 0.3
    },
    %{
      condition: "uses_parameterized_query",
      description: "File uses prepared statements",
      amount: 0.2
    },
    %{
      condition: "in_test_file",
      description: "File appears to be a test",
      amount: 0.4
    }
  ]
}
```

## Testing Your Migration

### 1. Validate Detection Accuracy
```elixir
# Run both patterns on test cases
test "enhanced pattern matches all original cases" do
  original = original_pattern()
  enhanced = enhanced_pattern()
  
  # Test vulnerable cases
  for code <- original.test_cases.vulnerable do
    assert Regex.match?(original.regex, code)
    assert matches_ast_rules?(enhanced.ast_rules, parse_code(code))
  end
  
  # Test safe cases
  for code <- original.test_cases.safe do
    refute Regex.match?(original.regex, code)
    refute matches_ast_rules?(enhanced.ast_rules, parse_code(code))
  end
end
```

### 2. Measure False Positive Reduction
```elixir
# Compare results on real codebases
test "enhanced pattern reduces false positives" do
  results_original = scan_with_pattern(codebase, original_pattern())
  results_enhanced = scan_with_pattern(codebase, enhanced_pattern())
  
  # Enhanced should find fewer but more accurate results
  assert length(results_enhanced) < length(results_original)
  assert accuracy(results_enhanced) > accuracy(results_original)
end
```

### 3. Performance Benchmarking
```elixir
# Ensure AST scanning performs well
bench "pattern performance" do
  %{
    "regex scan" => fn -> scan_with_regex(large_file) end,
    "ast scan" => fn -> scan_with_ast(large_file) end
  }
end
```

## Best Practices

1. **Keep Patterns Focused**: Each pattern should detect one specific vulnerability
2. **Document Thoroughly**: Explain what the AST rules are looking for
3. **Test Extensively**: Include edge cases and real-world examples
4. **Monitor Metrics**: Track detection rates and false positives
5. **Iterate Based on Feedback**: Refine rules based on user reports
6. **Version Patterns**: Track changes and improvements over time

## Gradual Migration Checklist

- [ ] Identify pattern for migration
- [ ] Analyze false positive reports
- [ ] Design AST rules
- [ ] Add context filtering
- [ ] Implement confidence scoring
- [ ] Create enhanced pattern
- [ ] Test with original test cases
- [ ] Test on real codebases
- [ ] Enable via feature flag
- [ ] Monitor in production
- [ ] Gather feedback
- [ ] Refine and optimize
- [ ] Document lessons learned

## Support and Resources

- Enhanced Pattern Documentation: `/docs/enhanced_patterns_guide.md`
- Example Patterns: `/lib/rsolv_api/security/patterns/javascript_enhanced.ex`
- Testing Guide: `/test/rsolv_api/security/enhanced_pattern_test.exs`
- API Reference: `GET /api/v1/patterns/enhanced`

For questions or assistance with pattern migration, contact the RSOLV security team.