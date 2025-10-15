defmodule Rsolv.Security.EnhancedPatternFormatTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.EnhancedPattern
  alias Rsolv.Security.Pattern

  describe "Enhanced format serialization" do
    test "to_enhanced_api_format includes all enhanced fields" do
      pattern = %EnhancedPattern{
        id: "test-enhanced",
        name: "Test Enhanced Pattern",
        description: "A test pattern with all enhanced features",
        type: :sql_injection,
        severity: :high,
        languages: ["javascript"],
        default_tier: :protected,
        recommendation: "Use parameterized queries",
        test_cases: %{
          vulnerable: ["db.query('SELECT * FROM users WHERE id = ' + userId)"],
          safe: ["db.query('SELECT * FROM users WHERE id = ?', [userId])"]
        },
        regex: ~r/SELECT.*FROM.*WHERE.*\+/i,
        ast_rules: [
          %{
            node_type: :binary_expression,
            properties: %{
              operator: "+",
              left: %{type: "Literal", value_pattern: ~r/SELECT.*FROM/i}
            },
            parent_context: :call_expression,
            child_must_contain: nil
          }
        ],
        context_rules: %{
          exclude_paths: ["test/", "spec/"],
          exclude_if_contains: ["// @rsolv-ignore", "/* rsolv-disable */"],
          require_imports: nil,
          require_context: ["database", "query"]
        },
        confidence_rules: %{
          base_confidence: 0.7,
          increase_if: [
            %{condition: "user_input_present", amount: 0.2},
            %{condition: "no_validation", amount: 0.1}
          ],
          decrease_if: [
            %{condition: "has_sanitization", amount: 0.3},
            %{condition: "in_test_file", amount: 0.2}
          ]
        },
        enhanced_recommendation: %{
          quick_fix: "Replace string concatenation with parameterized query",
          detailed_steps: [
            "1. Identify the SQL query construction",
            "2. Replace concatenation with placeholder syntax",
            "3. Pass user input as parameters array"
          ],
          references: [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
          ]
        },
        metadata: %{
          last_updated: "2025-01-10",
          author: "security-team",
          tags: ["database", "injection", "owasp-top-10"]
        }
      }

      formatted = EnhancedPattern.to_enhanced_api_format(pattern)

      # Check all fields are present
      assert formatted[:id] == "test-enhanced"
      assert formatted[:name] == "Test Enhanced Pattern"
      assert formatted[:supports_ast] == true
      assert is_list(formatted[:ast_rules])
      assert length(formatted[:ast_rules]) == 1
      assert is_map(formatted[:context_rules])
      assert is_map(formatted[:confidence_rules])
      assert is_map(formatted[:enhanced_recommendation])
      assert is_map(formatted[:metadata])

      # Check nested structures
      assert formatted[:context_rules][:exclude_paths] == ["test/", "spec/"]
      assert formatted[:confidence_rules][:base_confidence] == 0.7
      assert length(formatted[:confidence_rules][:increase_if]) == 2
      assert formatted[:enhanced_recommendation][:quick_fix] != nil
      assert length(formatted[:enhanced_recommendation][:detailed_steps]) == 3
    end

    test "to_enhanced_api_format handles patterns without AST rules" do
      pattern = %EnhancedPattern{
        id: "regex-only",
        name: "Regex Only Pattern",
        description: "Pattern using only regex",
        type: :xss,
        severity: :medium,
        languages: ["javascript"],
        default_tier: :public,
        recommendation: "Escape HTML entities",
        test_cases: %{
          vulnerable: ["element.innerHTML = userInput"],
          safe: ["element.textContent = userInput"]
        },
        regex: ~r/innerHTML\s*=\s*[^"']/,
        ast_rules: nil,
        context_rules: nil,
        confidence_rules: nil,
        enhanced_recommendation: nil,
        metadata: nil
      }

      formatted = EnhancedPattern.to_enhanced_api_format(pattern)

      assert formatted[:supports_ast] == false
      assert formatted[:ast_rules] == nil
      assert formatted[:regex] != nil
    end
  end

  describe "Backward compatibility" do
    test "enhanced pattern can be used as standard pattern" do
      enhanced = %EnhancedPattern{
        id: "backwards-compat",
        name: "Backwards Compatible",
        description: "Should work with old code",
        type: :hardcoded_secret,
        severity: :high,
        languages: ["python"],
        default_tier: :protected,
        recommendation: "Use environment variables",
        test_cases: %{
          vulnerable: ["api_key = 'sk-1234567890'"],
          safe: ["api_key = os.environ.get('API_KEY')"]
        },
        regex: ~r/api_key\s*=\s*["'][^"']+["']/,
        ast_rules: [
          %{
            node_type: :assignment,
            properties: %{
              left: %{name: "api_key"},
              right: %{type: "Literal"}
            },
            parent_context: nil,
            child_must_contain: nil
          }
        ]
      }

      # Convert to standard pattern
      standard = EnhancedPattern.to_pattern(enhanced)

      # Verify it's a valid Pattern struct
      assert %Pattern{} = standard
      assert Pattern.valid?(standard)

      # Check fields match
      assert standard.id == enhanced.id
      assert standard.name == enhanced.name
      assert standard.regex == enhanced.regex
      assert standard.test_cases == enhanced.test_cases
    end

    test "AST-only pattern generates fallback regex" do
      pattern = %EnhancedPattern{
        id: "ast-only-fallback",
        name: "AST Only With Fallback",
        description: "Should generate regex from AST",
        type: :command_injection,
        severity: :critical,
        languages: ["javascript"],
        default_tier: :protected,
        recommendation: "Use child_process.spawn with array args",
        test_cases: %{
          vulnerable: ["exec(userInput)"],
          safe: ["spawn('ls', ['-la'])"]
        },
        # No regex provided
        regex: nil,
        ast_rules: [
          %{
            node_type: :call_expression,
            properties: %{
              callee: %{name: "exec"}
            },
            parent_context: nil,
            child_must_contain: nil
          },
          %{
            node_type: :call_expression,
            properties: %{
              callee: %{name: "eval"}
            },
            parent_context: nil,
            child_must_contain: nil
          }
        ]
      }

      standard = EnhancedPattern.to_pattern(pattern)

      # Should have generated a regex
      assert standard.regex != nil
      assert Regex.regex?(standard.regex)

      # Should match the function names from AST rules
      assert Regex.match?(standard.regex, "exec(something)")
      assert Regex.match?(standard.regex, "eval(code)")
    end
  end

  describe "Validation enhancements" do
    test "validates AST rule node types" do
      valid_pattern =
        build_pattern(
          ast_rules: [
            %{
              node_type: :call_expression,
              properties: %{},
              parent_context: nil,
              child_must_contain: nil
            }
          ]
        )

      assert EnhancedPattern.valid?(valid_pattern)

      # Invalid node type (should be atom)
      invalid_pattern =
        build_pattern(
          ast_rules: [
            %{
              # String instead of atom
              node_type: "call_expression",
              properties: %{},
              parent_context: nil,
              child_must_contain: nil
            }
          ]
        )

      refute EnhancedPattern.valid?(invalid_pattern)
    end

    test "validates confidence rules structure" do
      valid_pattern =
        build_pattern(
          confidence_rules: %{
            base_confidence: 0.5,
            increase_if: [
              %{condition: "test", amount: 0.1}
            ],
            decrease_if: []
          }
        )

      assert EnhancedPattern.valid?(valid_pattern)

      # Invalid base confidence (out of range)
      invalid_pattern1 =
        build_pattern(
          confidence_rules: %{
            # > 1.0
            base_confidence: 1.5,
            increase_if: [],
            decrease_if: []
          }
        )

      refute EnhancedPattern.valid?(invalid_pattern1)

      # Missing required fields in modifiers
      invalid_pattern2 =
        build_pattern(
          confidence_rules: %{
            base_confidence: 0.5,
            increase_if: [
              # Missing amount
              %{condition: "test"}
            ],
            decrease_if: []
          }
        )

      refute EnhancedPattern.valid?(invalid_pattern2)
    end

    test "validates context rules keys" do
      valid_pattern =
        build_pattern(
          context_rules: %{
            exclude_paths: ["test/"],
            require_imports: ["express"],
            exclude_if_contains: nil,
            require_context: nil
          }
        )

      assert EnhancedPattern.valid?(valid_pattern)

      # Invalid key in context rules
      invalid_pattern =
        build_pattern(
          context_rules: %{
            exclude_paths: ["test/"],
            # Not allowed
            invalid_key: "value"
          }
        )

      refute EnhancedPattern.valid?(invalid_pattern)
    end
  end

  describe "Format conversion" do
    test "preserves all data through round-trip conversion" do
      original = build_complete_pattern()

      # Convert to API format and back
      api_format = EnhancedPattern.to_enhanced_api_format(original)

      # Verify all fields are preserved
      assert api_format[:id] == original.id
      assert api_format[:ast_rules] == original.ast_rules
      assert api_format[:context_rules] == original.context_rules
      assert api_format[:confidence_rules] == original.confidence_rules
      assert api_format[:enhanced_recommendation] == original.enhanced_recommendation
      assert api_format[:metadata] == original.metadata
    end

    test "handles nil optional fields gracefully" do
      minimal = %EnhancedPattern{
        id: "minimal",
        name: "Minimal Pattern",
        description: "Only required fields",
        type: :xss,
        severity: :low,
        languages: ["html"],
        default_tier: :public,
        recommendation: "Escape output",
        test_cases: %{vulnerable: ["<div>"], safe: ["&lt;div&gt;"]},
        regex: ~r/<script>/
      }

      api_format = EnhancedPattern.to_enhanced_api_format(minimal)

      assert api_format[:supports_ast] == false
      assert api_format[:ast_rules] == nil
      assert api_format[:context_rules] == nil
      assert api_format[:confidence_rules] == nil
      assert api_format[:enhanced_recommendation] == nil
    end
  end

  # Helper functions

  defp build_pattern(overrides \\ []) do
    base = %{
      id: "test",
      name: "Test Pattern",
      description: "Test",
      type: :xss,
      severity: :medium,
      languages: ["javascript"],
      default_tier: :public,
      recommendation: "Fix it",
      test_cases: %{vulnerable: ["bad"], safe: ["good"]},
      regex: ~r/test/
    }

    struct(EnhancedPattern, Enum.into(overrides, base))
  end

  defp build_complete_pattern do
    %EnhancedPattern{
      id: "complete",
      name: "Complete Pattern",
      description: "Pattern with all fields",
      type: :sql_injection,
      severity: :critical,
      languages: ["javascript", "typescript"],
      frameworks: ["express", "koa"],
      regex: ~r/SELECT.*FROM.*WHERE/i,
      default_tier: :protected,
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation: "Use parameterized queries",
      test_cases: %{
        vulnerable: ["query('SELECT * FROM users WHERE id = ' + id)"],
        safe: ["query('SELECT * FROM users WHERE id = ?', [id])"]
      },
      ast_rules: [
        %{
          node_type: :binary_expression,
          properties: %{operator: "+"},
          parent_context: :call_expression,
          child_must_contain: ["SELECT", "FROM", "WHERE"]
        }
      ],
      context_rules: %{
        exclude_paths: ["test/", "spec/", "migrations/"],
        exclude_if_contains: ["@no-check", "eslint-disable"],
        require_imports: ["mysql", "pg", "sqlite3"],
        require_context: ["database", "db", "query"]
      },
      confidence_rules: %{
        base_confidence: 0.6,
        increase_if: [
          %{condition: "user_controlled_input", amount: 0.3},
          %{condition: "no_input_validation", amount: 0.1}
        ],
        decrease_if: [
          %{condition: "has_prepared_statement", amount: 0.4},
          %{condition: "input_sanitized", amount: 0.2}
        ]
      },
      enhanced_recommendation: %{
        quick_fix: "Use ? placeholders: query('SELECT * FROM users WHERE id = ?', [id])",
        detailed_steps: [
          "Identify SQL query construction",
          "Replace string concatenation with placeholders",
          "Pass variables as parameter array"
        ],
        references: [
          "https://owasp.org/www-community/attacks/SQL_Injection"
        ]
      },
      metadata: %{
        created_at: "2025-01-10",
        updated_at: "2025-01-10",
        tags: ["database", "injection"],
        risk_score: 9.5
      }
    }
  end
end
