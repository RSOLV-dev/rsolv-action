defmodule Rsolv.AST.ConfidenceScorerRealisticTest do
  @moduledoc """
  Test-Driven Development tests for confidence scoring that reflect real-world scenarios.
  These tests verify that we maintain excellent confidence in avoiding false positives
  while still catching real vulnerabilities.
  """

  use ExUnit.Case, async: true
  alias Rsolv.AST.ConfidenceScorer

  describe "critical vulnerabilities without detected user input" do
    @tag :red_green_refactor
    test "eval() should be high confidence even without detected user input" do
      # RED: Currently fails (returns ~0.67)
      context = %{
        pattern_type: :code_injection,
        function_name: "eval",
        # Detection failed but it's still eval!
        has_user_input: false,
        ast_match: :exact
      }

      confidence = ConfidenceScorer.calculate_confidence(context, "javascript", %{})

      # eval is inherently dangerous - should still be reported
      assert confidence >= 0.75, "eval should have confidence >= 0.75, got #{confidence}"
    end

    @tag :red_green_refactor
    test "RCE patterns should be high confidence even without detected user input" do
      # RED: Currently fails (returns ~0.595)
      context = %{
        pattern_type: :rce,
        has_user_input: false,
        ast_match: :exact
      }

      confidence = ConfidenceScorer.calculate_confidence(context, "javascript", %{})

      assert confidence >= 0.70, "RCE should have confidence >= 0.70, got #{confidence}"
    end

    @tag :red_green_refactor
    test "exec() command injection should be high confidence" do
      # RED: Currently may fail
      context = %{
        pattern_type: :command_injection,
        # Detection might fail
        has_user_input: false,
        ast_match: :exact
      }

      confidence = ConfidenceScorer.calculate_confidence(context, "javascript", %{})

      assert confidence >= 0.70,
             "Command injection should have confidence >= 0.70, got #{confidence}"
    end
  end

  describe "patterns that don't require user input" do
    @tag :red_green_refactor
    test "hardcoded secrets should have high confidence without user input" do
      # RED: Currently fails (returns ~0.56)
      context = %{
        pattern_type: :hardcoded_secret,
        # Correct! Secrets don't have user input
        has_user_input: false,
        ast_match: :exact
      }

      confidence = ConfidenceScorer.calculate_confidence(context, "javascript", %{})

      # Hardcoded secrets are definite vulnerabilities
      assert confidence >= 0.80,
             "Hardcoded secrets should have confidence >= 0.80, got #{confidence}"
    end

    @tag :red_green_refactor
    test "weak crypto should have reasonable confidence without user input" do
      # RED: Likely fails
      context = %{
        pattern_type: :weak_crypto,
        # Crypto doesn't need user input
        has_user_input: false,
        ast_match: :exact
      }

      confidence = ConfidenceScorer.calculate_confidence(context, "javascript", %{})

      assert confidence >= 0.65, "Weak crypto should have confidence >= 0.65, got #{confidence}"
    end

    @tag :red_green_refactor
    test "insecure random should have reasonable confidence" do
      context = %{
        pattern_type: :insecure_random,
        # Math.random() doesn't need user input
        has_user_input: false,
        ast_match: :exact
      }

      confidence = ConfidenceScorer.calculate_confidence(context, "javascript", %{})

      assert confidence >= 0.60,
             "Insecure random should have confidence >= 0.60, got #{confidence}"
    end
  end

  describe "user input detection uncertainty" do
    @tag :red_green_refactor
    test "SQL injection with uncertain user input should still be reportable" do
      # RED: Currently fails (returns ~0.577)
      context = %{
        pattern_type: :sql_injection,
        # Uncertain detection
        has_user_input: false,
        in_database_call: true,
        ast_match: :exact
      }

      confidence = ConfidenceScorer.calculate_confidence(context, "javascript", %{})

      # Should be above threshold but with reduced confidence
      assert confidence >= 0.65, "SQL injection should have confidence >= 0.65, got #{confidence}"
      assert confidence < 0.85, "SQL injection without user input should be < 0.85"
    end

    @tag :red_green_refactor
    test "XSS with uncertain user input should be reportable with lower confidence" do
      context = %{
        pattern_type: :xss,
        has_user_input: false,
        ast_match: :exact
      }

      confidence = ConfidenceScorer.calculate_confidence(context, "javascript", %{})

      assert confidence >= 0.60, "XSS should have confidence >= 0.60, got #{confidence}"
      assert confidence < 0.80, "XSS without user input should be < 0.80"
    end
  end

  describe "false positive reduction for safe patterns" do
    test "framework protection should significantly reduce confidence" do
      # This is working correctly
      context = %{
        pattern_type: :sql_injection,
        has_user_input: true,
        # Using ORM
        framework_protection: true,
        ast_match: :exact
      }

      confidence = ConfidenceScorer.calculate_confidence(context, "javascript", %{})

      assert confidence < 0.50, "Framework protection should reduce confidence below 0.50"
    end

    test "test files should have very low confidence" do
      # This is working correctly  
      context = %{
        pattern_type: :sql_injection,
        has_user_input: true,
        file_path: "spec/models/user_spec.rb",
        ast_match: :exact
      }

      confidence = ConfidenceScorer.calculate_confidence(context, "ruby", %{})

      assert confidence < 0.40, "Test files should have confidence < 0.40"
    end
  end

  describe "confidence thresholds per vulnerability type" do
    @tag :red_green_refactor
    test "different vulnerability types should have appropriate minimum thresholds" do
      test_cases = [
        # Critical vulnerabilities - lower threshold to catch more
        {:rce, false, 0.65},
        {:code_injection, false, 0.65},
        {:command_injection, false, 0.65},

        # High severity - slightly higher threshold
        {:sql_injection, false, 0.60},
        {:xss, false, 0.60},

        # Non-input vulnerabilities - should not be penalized
        {:hardcoded_secret, false, 0.75},
        {:weak_crypto, false, 0.60},
        {:insecure_random, false, 0.55}
      ]

      for {pattern_type, has_user_input, min_confidence} <- test_cases do
        context = %{
          pattern_type: pattern_type,
          has_user_input: has_user_input,
          ast_match: :exact
        }

        confidence = ConfidenceScorer.calculate_confidence(context, "javascript", %{})

        assert confidence >= min_confidence,
               "#{pattern_type} should have confidence >= #{min_confidence}, got #{confidence}"
      end
    end
  end

  describe "doctests and examples" do
    @tag :doctest
    test "confidence calculation examples from documentation" do
      # These should match any examples in the module's @moduledoc or @doc

      # Example 1: Perfect storm scenario
      perfect_storm = %{
        pattern_type: :sql_injection,
        ast_match: :exact,
        has_user_input: true,
        in_database_call: true,
        framework_protection: false
      }

      confidence = ConfidenceScorer.calculate_confidence(perfect_storm, "php", %{})
      assert confidence >= 0.90, "Perfect storm should have very high confidence"

      # Example 2: Uncertain scenario
      uncertain = %{
        pattern_type: :xss,
        ast_match: :partial,
        has_user_input: false,
        framework_protection: false
      }

      confidence = ConfidenceScorer.calculate_confidence(uncertain, "javascript", %{})

      assert confidence >= 0.40 and confidence <= 0.60,
             "Uncertain scenario should have medium-low confidence"
    end
  end
end
