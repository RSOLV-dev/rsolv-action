defmodule RsolvApi.AST.FallbackStrategyTest do
  use ExUnit.Case, async: false

  alias RsolvApi.AST.{FallbackStrategy, ParserRegistry, SessionManager}

  setup do
    # Ensure application is started
    Application.ensure_all_started(:rsolv_api)
    
    # Create test session
    {:ok, session} = SessionManager.create_session("test-customer")
    
    %{session_id: session.id, customer_id: "test-customer"}
  end

  describe "fallback strategy for AST parsing failures" do
    test "returns basic structure analysis when AST parsing fails", %{session_id: session_id, customer_id: customer_id} do
      # Code that will fail AST parsing
      invalid_code = """
      function test() {
        const x = ;  // syntax error
        return x;
      }
      """
      
      {:ok, result} = FallbackStrategy.analyze_with_fallback(
        session_id, 
        customer_id, 
        "javascript", 
        invalid_code
      )
      
      assert result.strategy == :fallback
      assert result.ast_available == false
      assert result.error != nil
      assert result.fallback_analysis != nil
      
      # Check fallback analysis structure
      assert Map.has_key?(result.fallback_analysis, :structure)
      assert Map.has_key?(result.fallback_analysis, :metrics)
      assert Map.has_key?(result.fallback_analysis, :patterns_detected)
      assert Map.has_key?(result.fallback_analysis, :confidence)
      
      # Verify basic structure detection
      assert result.fallback_analysis.structure.has_functions == true
      assert result.fallback_analysis.structure.has_variables == true
      assert result.fallback_analysis.metrics.line_count == 4
    end

    test "uses AST when parsing succeeds", %{session_id: session_id, customer_id: customer_id} do
      valid_code = """
      function test() {
        const x = 42;
        return x;
      }
      """
      
      {:ok, result} = FallbackStrategy.analyze_with_fallback(
        session_id, 
        customer_id, 
        "javascript", 
        valid_code
      )
      
      assert result.strategy == :ast
      assert result.ast_available == true
      assert result.ast != nil
      assert result.error == nil
      assert result.fallback_analysis == nil
    end

    test "fallback detects common security patterns without AST", %{session_id: session_id, customer_id: customer_id} do
      vulnerable_code = """
      const query = "SELECT * FROM users WHERE id = " + userId;
      db.execute(query);
      """
      
      {:ok, result} = FallbackStrategy.analyze_with_fallback(
        session_id, 
        customer_id, 
        "javascript", 
        vulnerable_code <> "const x = ;" # Add syntax error to force fallback
      )
      
      assert result.strategy == :fallback
      assert length(result.fallback_analysis.patterns_detected) > 0
      
      sql_injection = Enum.find(result.fallback_analysis.patterns_detected, fn p ->
        p.type == "sql_injection"
      end)
      
      assert sql_injection != nil
      assert sql_injection.confidence < 1.0  # Lower confidence without AST
      assert sql_injection.confidence >= 0.6  # But still reasonable
    end

    test "fallback handles parser timeout gracefully", %{session_id: session_id, customer_id: customer_id} do
      timeout_code = "FORCE_TIMEOUT_SIGNAL"
      
      {:ok, result} = FallbackStrategy.analyze_with_fallback(
        session_id, 
        customer_id, 
        "javascript", 
        timeout_code
      )
      
      assert result.strategy == :fallback
      assert result.error.type == :timeout
      assert result.fallback_analysis != nil
      assert result.fallback_analysis.confidence < 0.5  # Low confidence for timeout
    end

    test "fallback handles parser crash gracefully", %{session_id: session_id, customer_id: customer_id} do
      crash_code = "FORCE_CRASH_SIGNAL"
      
      {:ok, result} = FallbackStrategy.analyze_with_fallback(
        session_id, 
        customer_id, 
        "javascript", 
        crash_code
      )
      
      assert result.strategy == :fallback
      assert result.error.type == :parser_crash
      assert result.fallback_analysis != nil
    end

    test "fallback provides language-specific pattern detection" do
      # Create a valid session
      {:ok, session} = SessionManager.create_session("test-customer")
      
      test_cases = [
        {
          "python",
          """
          import os
          os.system("rm -rf " + user_input)
          """,
          "command_injection"
        },
        {
          "ruby",
          """
          system("echo " + params[:message])
          """,
          "command_injection"
        },
        {
          "php",
          """
          <?php
          $query = "SELECT * FROM users WHERE id = " . $_GET['id'];
          mysql_query($query);
          ?>
          """,
          "sql_injection"
        }
      ]
      
      for {language, code, expected_pattern} <- test_cases do
        {:ok, result} = FallbackStrategy.analyze_with_fallback(
          session.id, 
          "test-customer", 
          language, 
          code <> " <?php syntax error"  # Force fallback
        )
        
        assert result.strategy == :fallback
        patterns = result.fallback_analysis.patterns_detected
        assert Enum.any?(patterns, &(&1.type == expected_pattern))
      end
    end

    test "fallback calculates reasonable confidence scores" do
      # Create a valid session
      {:ok, session} = SessionManager.create_session("test-customer")
      
      # Test different code complexities
      simple_code = "const x = 1;"
      complex_code = """
      function complexFunction() {
        try {
          const result = someAPI.call();
          if (result.status === 'success') {
            return processData(result.data);
          }
        } catch (error) {
          console.error(error);
        }
      }
      """
      
      {:ok, simple_result} = FallbackStrategy.analyze_with_fallback(
        session.id, 
        "test-customer", 
        "javascript", 
        simple_code <> " const err = ;"  # syntax error
      )
      
      {:ok, complex_result} = FallbackStrategy.analyze_with_fallback(
        session.id, 
        "test-customer", 
        "javascript", 
        complex_code <> " const err = ;"  # syntax error
      )
      
      # More complex code should have lower confidence in fallback
      assert simple_result.fallback_analysis.confidence > complex_result.fallback_analysis.confidence
    end

    test "fallback includes partial AST information when available" do
      # Create a valid session
      {:ok, session} = SessionManager.create_session("test-customer")
      
      # Code with partial parse-able structure
      partial_code = """
      function validFunction() {
        return 42;
      }
      
      function invalidFunction() {
        const x = ;  // This will cause parse failure
      }
      """
      
      {:ok, result} = FallbackStrategy.analyze_with_fallback(
        session.id, 
        "test-customer", 
        "javascript", 
        partial_code
      )
      
      assert result.strategy == :fallback
      assert result.fallback_analysis.partial_ast_available == true
      assert result.fallback_analysis.parsed_sections > 0
    end

    test "fallback strategy is configurable", %{session_id: session_id, customer_id: customer_id} do
      options = %{
        fallback_enabled: false,
        fallback_on_timeout: false
      }
      
      invalid_code = "const x = ;"
      
      {:error, error} = FallbackStrategy.analyze_with_fallback(
        session_id, 
        customer_id, 
        "javascript", 
        invalid_code,
        options
      )
      
      # Should fail without fallback
      assert error.type == :syntax_error
    end

    test "fallback provides actionable recommendations" do
      # Create a valid session
      {:ok, session} = SessionManager.create_session("test-customer")
      
      vulnerable_code = """
      eval(userInput);
      exec(command + userParam);
      """
      
      {:ok, result} = FallbackStrategy.analyze_with_fallback(
        session.id, 
        "test-customer", 
        "javascript", 
        vulnerable_code <> "const err = ;"
      )
      
      assert result.strategy == :fallback
      recommendations = result.fallback_analysis.recommendations
      
      assert length(recommendations) > 0
      assert Enum.any?(recommendations, &String.contains?(&1, "eval"))
      assert Enum.any?(recommendations, &String.contains?(&1, "exec"))
    end

    test "fallback tracks performance metrics" do
      # Create a valid session
      {:ok, session} = SessionManager.create_session("test-customer")
      
      code = "const x = 1;"
      
      {:ok, result} = FallbackStrategy.analyze_with_fallback(
        session.id, 
        "test-customer", 
        "javascript", 
        code <> "const err = ;"
      )
      
      assert result.timing != nil
      assert result.timing.ast_attempt_ms != nil
      assert result.timing.fallback_analysis_ms != nil
      assert result.timing.total_ms != nil
      assert result.timing.total_ms >= result.timing.fallback_analysis_ms
    end

    test "fallback handles empty and nil code gracefully" do
      # Create a valid session
      {:ok, session} = SessionManager.create_session("test-customer")
      
      for code <- ["", nil] do
        {:ok, result} = FallbackStrategy.analyze_with_fallback(
          session.id, 
          "test-customer", 
          "javascript", 
          code
        )
        
        assert result.strategy == :fallback
        assert result.fallback_analysis.metrics.line_count == 0
        assert result.fallback_analysis.patterns_detected == []
        assert result.fallback_analysis.confidence == 0.0
      end
    end

    test "fallback provides different analysis depth levels" do
      # Create a valid session
      {:ok, session} = SessionManager.create_session("test-customer")
      
      code = """
      function test() {
        const password = "hardcoded123";
        return password;
      }
      """
      
      # Quick analysis
      {:ok, quick} = FallbackStrategy.analyze_with_fallback(
        session.id, 
        "test-customer", 
        "javascript", 
        code <> "const err = ;",
        %{analysis_depth: :quick}
      )
      
      # Deep analysis
      {:ok, deep} = FallbackStrategy.analyze_with_fallback(
        session.id, 
        "test-customer", 
        "javascript", 
        code <> "const err = ;",
        %{analysis_depth: :deep}
      )
      
      # Deep analysis should find more patterns
      assert length(deep.fallback_analysis.patterns_detected) >= 
             length(quick.fallback_analysis.patterns_detected)
      
      # Deep analysis should take more time
      assert deep.timing.fallback_analysis_ms >= quick.timing.fallback_analysis_ms
    end

    test "fallback integrates with existing security patterns" do
      # Create a valid session
      {:ok, session} = SessionManager.create_session("test-customer")
      
      code = """
      const crypto = require('crypto');
      const key = crypto.randomBytes(8);  // Weak key generation
      """
      
      {:ok, result} = FallbackStrategy.analyze_with_fallback(
        session.id, 
        "test-customer", 
        "javascript", 
        code <> "const err = ;"
      )
      
      assert result.strategy == :fallback
      
      weak_crypto = Enum.find(result.fallback_analysis.patterns_detected, fn p ->
        p.type == "weak_cryptography"
      end)
      
      assert weak_crypto != nil
      assert weak_crypto.metadata.key_size == 8
    end

    test "fallback caches analysis results for performance" do
      # Create a valid session
      {:ok, session} = SessionManager.create_session("test-customer")
      
      code = "const x = 1; const y = 2;"
      
      # First call
      {:ok, result1} = FallbackStrategy.analyze_with_fallback(
        session.id, 
        "test-customer", 
        "javascript", 
        code <> "const err = ;"
      )
      
      # Second call with same code
      {:ok, result2} = FallbackStrategy.analyze_with_fallback(
        session.id, 
        "test-customer", 
        "javascript", 
        code <> "const err = ;"
      )
      
      # Second call should be faster (cache hit)
      assert result2.timing.cache_hit == true
      assert result2.timing.total_ms < result1.timing.total_ms
      
      # Results should be equivalent
      assert result1.fallback_analysis.patterns_detected == 
             result2.fallback_analysis.patterns_detected
    end
  end

  describe "fallback strategy error handling" do
    test "handles invalid language gracefully" do
      # Create a valid session first
      {:ok, session} = SessionManager.create_session("test-customer")
      
      {:error, error} = FallbackStrategy.analyze_with_fallback(
        session.id, 
        "test-customer", 
        "cobol", 
        "IDENTIFICATION DIVISION."
      )
      
      assert error.type == :unsupported_language
      assert error.supported_languages != nil
    end

    test "handles analysis errors gracefully" do
      # Create a valid session
      {:ok, session} = SessionManager.create_session("test-customer")
      
      # Code that might cause analysis issues
      problematic_code = String.duplicate("(", 10000)  # Deeply nested
      
      {:ok, result} = FallbackStrategy.analyze_with_fallback(
        session.id, 
        "test-customer", 
        "javascript", 
        problematic_code
      )
      
      assert result.strategy == :fallback
      assert result.fallback_analysis != nil
      assert result.fallback_analysis.analysis_warnings != nil
      assert length(result.fallback_analysis.analysis_warnings) > 0
    end
  end
end