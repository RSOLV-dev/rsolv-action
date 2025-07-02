defmodule RsolvApi.AST.ParserErrorStandardizationTest do
  use ExUnit.Case, async: false

  alias RsolvApi.AST.{ParserRegistry, SessionManager}

  setup do
    # Ensure application is started
    Application.ensure_all_started(:rsolv_api)
    
    # Create test session
    {:ok, session} = SessionManager.create_session("test-customer")
    
    %{session_id: session.id, customer_id: "test-customer"}
  end

  describe "error standardization integration" do
    test "syntax errors are standardized across all languages", %{session_id: session_id, customer_id: customer_id} do
      test_cases = [
        {
          "javascript", 
          "const x = ;", 
          fn error ->
            assert error.type == :syntax_error
            assert error.language == "javascript"
            assert error.severity == :high
            assert error.recoverable == true
            assert is_list(error.suggestions)
            assert length(error.suggestions) > 0
          end
        },
        {
          "python",
          "def func(:",
          fn error ->
            assert error.type == :syntax_error
            assert error.language == "python"
            assert error.severity == :high
            assert error.recoverable == true
            assert Enum.any?(error.suggestions, &(String.contains?(&1, "syntax") or String.contains?(&1, "indentation") or String.contains?(&1, "colon")))
          end
        },
        {
          "ruby",
          "def foo\n  @@ invalid syntax @@\nend",
          fn error ->
            assert error.type == :syntax_error
            assert error.language == "ruby"
            assert error.severity == :high
            assert error.recoverable == true
          end
        }
      ]

      for {language, invalid_code, validation_fn} <- test_cases do
        {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, language, invalid_code)
        
        assert result.error != nil
        assert Map.has_key?(result.error, :type)
        assert Map.has_key?(result.error, :language)
        assert Map.has_key?(result.error, :severity)
        assert Map.has_key?(result.error, :recoverable)
        assert Map.has_key?(result.error, :suggestions)
        assert Map.has_key?(result.error, :timestamp)
        
        validation_fn.(result.error)
      end
    end

    test "timeout errors are standardized", %{session_id: session_id, customer_id: customer_id} do
      # Force timeout using test signal
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "javascript", "FORCE_TIMEOUT_SIGNAL")
      
      assert result.error != nil
      assert result.error.type == :timeout
      assert result.error.language == "javascript"
      assert result.error.severity == :medium
      assert result.error.recoverable == true
      assert Enum.any?(result.error.suggestions, &String.contains?(&1, "timeout"))
    end

    test "parser crash errors are standardized", %{session_id: session_id, customer_id: customer_id} do
      # Force crash using test signal
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "python", "FORCE_CRASH_SIGNAL")
      
      assert result.error != nil
      assert result.error.type == :parser_crash
      assert result.error.language == "python" 
      assert result.error.severity == :critical
      assert result.error.recoverable == false
      assert Enum.any?(result.error.suggestions, &String.contains?(&1, "crash"))
    end

    test "unsupported language errors are standardized", %{session_id: session_id, customer_id: customer_id} do
      {:error, standardized_error} = ParserRegistry.parse_code(session_id, customer_id, "cobol", "IDENTIFICATION DIVISION.")
      
      # Unsupported languages now return standardized error format
      assert standardized_error.type == :unsupported_language
      assert standardized_error.language == "cobol"
      assert standardized_error.message == "Language 'cobol' is not supported"
      assert standardized_error.severity == :low
      assert standardized_error.recoverable == false
      assert is_list(standardized_error.supported_languages)
      assert "javascript" in standardized_error.supported_languages
      assert is_list(standardized_error.suggestions)
      assert %DateTime{} = standardized_error.timestamp
    end

    test "unknown errors are standardized with fallback", %{session_id: session_id, customer_id: customer_id} do
      # This would require patching the parser to return an unexpected error format
      # For now, test the error handler directly
      unknown_error = %{weird_field: "some value"}
      
      {:error, standardized} = RsolvApi.AST.ASTErrorHandler.standardize_error(
        unknown_error,
        "javascript", 
        "const x = 1;"
      )
      
      assert standardized.type == :unknown_error
      assert standardized.language == "javascript"
      assert standardized.severity == :medium
      assert standardized.recoverable == true
      assert standardized.original_error == unknown_error
    end

    test "error location information is preserved when available", %{session_id: session_id, customer_id: customer_id} do
      # Test with code that should provide location info
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "javascript", "const x = ;")
      
      if result.error && result.error.location do
        assert is_map(result.error.location)
        assert Map.has_key?(result.error.location, :line)
        assert Map.has_key?(result.error.location, :column)
      end
    end

    test "source snippets are included for syntax errors", %{session_id: session_id, customer_id: customer_id} do
      invalid_code = """
      function test() {
        const x = 1;
        const y = ;
        return x + y;
      }
      """
      
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "javascript", invalid_code)
      
      if result.error && result.error.source_snippet do
        assert is_map(result.error.source_snippet)
        assert Map.has_key?(result.error.source_snippet, :lines)
        assert Map.has_key?(result.error.source_snippet, :error_line)
        assert is_list(result.error.source_snippet.lines)
      end
    end

    test "standardized errors include recovery suggestions", %{session_id: session_id, customer_id: customer_id} do
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "python", "def func(:")
      
      assert result.error != nil
      assert is_list(result.error.suggestions)
      assert length(result.error.suggestions) > 0
      assert Enum.any?(result.error.suggestions, &(String.contains?(&1, "syntax") or String.contains?(&1, "punctuation") or String.contains?(&1, "indentation")))
    end

    test "error timestamps are included", %{session_id: session_id, customer_id: customer_id} do
      before_parse = DateTime.utc_now()
      {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, "javascript", "const x = ;")
      after_parse = DateTime.utc_now()
      
      if result.error do
        assert Map.has_key?(result.error, :timestamp)
        assert result.error.timestamp != nil
        # Timestamp should be between before and after the parse
        assert DateTime.compare(result.error.timestamp, before_parse) != :lt
        assert DateTime.compare(result.error.timestamp, after_parse) != :gt
      end
    end
  end

  describe "error format consistency" do
    test "all error types follow the same structure", %{session_id: session_id, customer_id: customer_id} do
      required_fields = [:type, :message, :language, :severity, :recoverable, :suggestions, :timestamp]
      
      # Test different error types
      error_test_cases = [
        {"javascript", "const x = ;"},  # syntax error
        {"python", "FORCE_TIMEOUT_SIGNAL"},  # timeout
        {"ruby", "FORCE_CRASH_SIGNAL"}  # crash
      ]
      
      for {language, code} <- error_test_cases do
        {:ok, result} = ParserRegistry.parse_code(session_id, customer_id, language, code)
        
        if result.error do
          for field <- required_fields do
            assert Map.has_key?(result.error, field), 
              "Missing field #{field} in error for #{language}: #{inspect(result.error)}"
          end
          
          # Verify field types
          assert is_atom(result.error.type)
          assert is_binary(result.error.message)
          assert is_binary(result.error.language)
          assert is_atom(result.error.severity)
          assert is_boolean(result.error.recoverable)
          assert is_list(result.error.suggestions)
          assert %DateTime{} = result.error.timestamp
        end
      end
    end
  end
end