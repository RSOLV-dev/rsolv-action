defmodule Rsolv.AST.ConfidenceScorerTest do
  use ExUnit.Case, async: false  # Changed: parser pool is singleton, must run sequentially

  alias Rsolv.AST.ConfidenceScorer

  describe "calculate_confidence/3" do
    test "high confidence for exact AST pattern match with security context" do
      match_context = %{
        pattern_type: :sql_injection,
        ast_match: :exact,
        has_user_input: true,
        in_database_call: true,
        framework_protection: false
      }

      confidence = ConfidenceScorer.calculate_confidence(match_context, "python", %{})

      assert confidence >= 0.9
      assert confidence <= 1.0
    end

    test "medium confidence for pattern match without clear user input" do
      match_context = %{
        pattern_type: :sql_injection,
        ast_match: :exact,
        has_user_input: false,
        in_database_call: true,
        framework_protection: false
      }

      confidence = ConfidenceScorer.calculate_confidence(match_context, "python", %{})

      assert confidence >= 0.5
      assert confidence < 0.8
    end

    test "low confidence when framework protection is detected" do
      match_context = %{
        pattern_type: :sql_injection,
        ast_match: :exact,
        has_user_input: true,
        in_database_call: true,
        # Using ORM or parameterized queries
        framework_protection: true
      }

      confidence = ConfidenceScorer.calculate_confidence(match_context, "python", %{})

      assert confidence < 0.5
    end

    test "adjusts confidence based on code complexity" do
      simple_context = %{
        pattern_type: :xss,
        ast_match: :exact,
        has_user_input: true,
        code_complexity: :low
      }

      complex_context = %{
        pattern_type: :xss,
        ast_match: :exact,
        has_user_input: true,
        code_complexity: :high
      }

      simple_confidence = ConfidenceScorer.calculate_confidence(simple_context, "javascript", %{})

      complex_confidence =
        ConfidenceScorer.calculate_confidence(complex_context, "javascript", %{})

      assert simple_confidence > complex_confidence
    end

    test "increases confidence for critical patterns like eval" do
      eval_context = %{
        pattern_type: :code_injection,
        function_name: "eval",
        has_user_input: true
      }

      confidence = ConfidenceScorer.calculate_confidence(eval_context, "javascript", %{})

      assert confidence >= 0.95
    end

    test "considers language-specific factors" do
      # PHP is more prone to certain vulnerabilities
      php_context = %{
        pattern_type: :sql_injection,
        ast_match: :exact,
        has_user_input: true
      }

      python_context = %{
        pattern_type: :sql_injection,
        ast_match: :exact,
        has_user_input: true
      }

      php_confidence = ConfidenceScorer.calculate_confidence(php_context, "php", %{})
      python_confidence = ConfidenceScorer.calculate_confidence(python_context, "python", %{})

      # PHP should have slightly higher confidence due to language characteristics
      assert php_confidence >= python_confidence
    end

    test "reduces confidence in test files" do
      prod_context = %{
        pattern_type: :hardcoded_secret,
        ast_match: :exact,
        file_path: "app/models/user.rb"
      }

      test_context = %{
        pattern_type: :hardcoded_secret,
        ast_match: :exact,
        file_path: "spec/models/user_spec.rb"
      }

      prod_confidence = ConfidenceScorer.calculate_confidence(prod_context, "ruby", %{})
      test_confidence = ConfidenceScorer.calculate_confidence(test_context, "ruby", %{})

      assert prod_confidence > test_confidence
      # Very low confidence in test files
      assert test_confidence < 0.3
    end

    test "considers pattern severity in confidence calculation" do
      high_severity_context = %{
        pattern_type: :remote_code_execution,
        ast_match: :exact,
        has_user_input: true
      }

      low_severity_context = %{
        pattern_type: :weak_random,
        ast_match: :exact
      }

      high_confidence =
        ConfidenceScorer.calculate_confidence(high_severity_context, "python", %{})

      low_confidence = ConfidenceScorer.calculate_confidence(low_severity_context, "python", %{})

      assert high_confidence > low_confidence
    end

    test "handles partial AST matches with reduced confidence" do
      exact_match = %{
        pattern_type: :sql_injection,
        ast_match: :exact,
        has_user_input: true
      }

      partial_match = %{
        pattern_type: :sql_injection,
        ast_match: :partial,
        has_user_input: true
      }

      exact_confidence = ConfidenceScorer.calculate_confidence(exact_match, "javascript", %{})
      partial_confidence = ConfidenceScorer.calculate_confidence(partial_match, "javascript", %{})

      assert exact_confidence > partial_confidence
      # Still reportable but lower
      assert partial_confidence >= 0.4
    end

    test "integrates multiple factors for final score" do
      context = %{
        pattern_type: :sql_injection,
        ast_match: :exact,
        has_user_input: true,
        in_database_call: true,
        framework_protection: false,
        code_complexity: :medium,
        file_path: "app/controllers/user_controller.rb",
        taint_analysis: %{
          user_input_sources: ["params[:id]"],
          sanitization_applied: false
        }
      }

      confidence = ConfidenceScorer.calculate_confidence(context, "ruby", %{})

      # With all these positive indicators, confidence should be high
      assert confidence >= 0.85
      assert confidence <= 0.95
    end
  end

  describe "explain_confidence/3" do
    test "provides human-readable explanation of confidence factors" do
      context = %{
        pattern_type: :sql_injection,
        ast_match: :exact,
        has_user_input: true,
        framework_protection: true
      }

      explanation = ConfidenceScorer.explain_confidence(context, "python", %{})

      assert String.contains?(explanation, "User input detected")
      assert String.contains?(explanation, "Framework protection")
      assert String.contains?(explanation, "confidence")
    end
  end
end
