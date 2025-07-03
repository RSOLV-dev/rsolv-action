defmodule Rsolv.AST.ASTErrorHandlerTest do
  use ExUnit.Case, async: true

  alias Rsolv.AST.ASTErrorHandler

  describe "standardize_error/3" do
    test "standardizes syntax errors with location information" do
      javascript_syntax_error = %{
        type: :syntax_error,
        message: "Unexpected token ';'",
        line: 5,
        column: 10,
        offset: 42
      }

      {:error, standardized} = ASTErrorHandler.standardize_error(
        javascript_syntax_error,
        "javascript",
        "const x = ;"
      )

      assert standardized.type == :syntax_error
      assert standardized.message == "Unexpected token ';'"
      assert standardized.language == "javascript"
      assert standardized.location.line == 5
      assert standardized.location.column == 10
      assert standardized.location.offset == 42
      assert standardized.source_snippet != nil
    end

    test "standardizes Python syntax errors" do
      python_syntax_error = %{
        type: :syntax_error,
        message: "invalid syntax",
        lineno: 3,
        offset: 8,
        text: "def func(:"
      }

      {:error, standardized} = ASTErrorHandler.standardize_error(
        python_syntax_error,
        "python",
        "def func(:"
      )

      assert standardized.type == :syntax_error
      assert standardized.message == "invalid syntax"
      assert standardized.language == "python"
      assert standardized.location.line == 3
      assert standardized.location.column == 8
    end

    test "standardizes Ruby parser errors" do
      ruby_parse_error = %{
        type: :parse_error,
        message: "unexpected token $end",
        location: %{line: 2, column: 5}
      }

      {:error, standardized} = ASTErrorHandler.standardize_error(
        ruby_parse_error,
        "ruby",
        "class Foo\n"
      )

      assert standardized.type == :syntax_error
      assert standardized.message == "unexpected token $end"
      assert standardized.language == "ruby"
      assert standardized.location.line == 2
      assert standardized.location.column == 5
    end

    test "standardizes PHP parser errors" do
      php_parse_error = %{
        type: :parse_error,
        message: "Syntax error, unexpected T_VARIABLE",
        line: 4,
        column: 12
      }

      {:error, standardized} = ASTErrorHandler.standardize_error(
        php_parse_error,
        "php",
        "<?php $var $ = 5;"
      )

      assert standardized.type == :syntax_error
      assert standardized.message == "Syntax error, unexpected T_VARIABLE"
      assert standardized.language == "php"
      assert standardized.location.line == 4
      assert standardized.location.column == 12
    end

    test "standardizes Java parser errors" do
      java_parse_error = %{
        type: :parse_error,
        message: "Parse error at line 6, column 4",
        line: 6,
        column: 4
      }

      {:error, standardized} = ASTErrorHandler.standardize_error(
        java_parse_error,
        "java",
        "public class Test {\n  public void method( {\n  }\n}"
      )

      assert standardized.type == :syntax_error
      assert standardized.language == "java"
      assert standardized.location.line == 6
      assert standardized.location.column == 4
    end

    test "standardizes Go parser errors" do
      go_parse_error = %{
        type: :scanner_error,
        message: "expected ')', found 'EOF'",
        pos: %{line: 3, column: 15, offset: 45}
      }

      {:error, standardized} = ASTErrorHandler.standardize_error(
        go_parse_error,
        "go",
        "func main() {\n  fmt.Println(\n}"
      )

      assert standardized.type == :syntax_error
      assert standardized.message == "expected ')', found 'EOF'"
      assert standardized.language == "go"
      assert standardized.location.line == 3
      assert standardized.location.column == 15
      assert standardized.location.offset == 45
    end

    test "standardizes timeout errors" do
      timeout_error = %{type: :timeout, duration_ms: 5000}

      {:error, standardized} = ASTErrorHandler.standardize_error(
        timeout_error,
        "javascript",
        "very large source code..."
      )

      assert standardized.type == :timeout
      assert standardized.message == "Parser timeout after 5000ms"
      assert standardized.language == "javascript"
      assert standardized.duration_ms == 5000
      assert standardized.location == nil
    end

    test "standardizes parser crash errors" do
      crash_error = %{
        type: :parser_crash,
        reason: :segmentation_fault,
        exit_code: 139
      }

      {:error, standardized} = ASTErrorHandler.standardize_error(
        crash_error,
        "php",
        "<?php some code"
      )

      assert standardized.type == :parser_crash
      assert standardized.message == "Parser crashed: segmentation_fault (exit code: 139)"
      assert standardized.language == "php"
      assert standardized.reason == :segmentation_fault
      assert standardized.exit_code == 139
    end

    test "standardizes unsupported language errors" do
      {:error, standardized} = ASTErrorHandler.standardize_error(
        %{type: :unsupported_language},
        "cobol",
        "IDENTIFICATION DIVISION."
      )

      assert standardized.type == :unsupported_language
      assert standardized.message == "Language 'cobol' is not supported"
      assert standardized.language == "cobol"
      assert standardized.supported_languages == ["javascript", "typescript", "python", "ruby", "php", "java", "go"]
    end

    test "standardizes unknown errors with fallback" do
      unknown_error = %{weird_field: "some value"}

      {:error, standardized} = ASTErrorHandler.standardize_error(
        unknown_error,
        "javascript",
        "const x = 1;"
      )

      assert standardized.type == :unknown_error
      assert standardized.message == "Unknown parsing error occurred"
      assert standardized.language == "javascript"
      assert standardized.original_error == unknown_error
    end
  end

  describe "extract_source_snippet/3" do
    test "extracts relevant source code snippet around error location" do
      source = """
      function test() {
        const x = 1;
        const y = ;
        return x + y;
      }
      """

      snippet = ASTErrorHandler.extract_source_snippet(source, 3, 10, context_lines: 1)

      expected_lines = [
        "  const x = 1;",
        "  const y = ;     <-- Error here",
        "  return x + y;"
      ]

      assert snippet.lines == expected_lines
      assert snippet.error_line == 3
      assert snippet.error_column == 10
    end

    test "handles source snippet at beginning of file" do
      source = """
      const x = ;
      const y = 2;
      """

      snippet = ASTErrorHandler.extract_source_snippet(source, 1, 10, context_lines: 2)

      expected_lines = [
        "const x = ;     <-- Error here",
        "const y = 2;"
      ]

      assert snippet.lines == expected_lines
      assert snippet.error_line == 1
      assert snippet.error_column == 10
    end

    test "handles source snippet at end of file" do
      source = """
      const x = 1;
      const y = 2;
      const z = ;
      """

      snippet = ASTErrorHandler.extract_source_snippet(source, 3, 10, context_lines: 1)

      expected_lines = [
        "const y = 2;",
        "const z = ;     <-- Error here"
      ]

      assert snippet.lines == expected_lines
      assert snippet.error_line == 3
      assert snippet.error_column == 10
    end

    test "returns nil for invalid line numbers" do
      source = "const x = 1;"
      snippet = ASTErrorHandler.extract_source_snippet(source, 5, 1)

      assert snippet == nil
    end
  end

  describe "categorize_error_severity/1" do
    test "categorizes syntax errors as high severity" do
      error = %{type: :syntax_error, message: "Unexpected token"}
      assert ASTErrorHandler.categorize_error_severity(error) == :high
    end

    test "categorizes parser crashes as critical severity" do
      error = %{type: :parser_crash, reason: :segmentation_fault}
      assert ASTErrorHandler.categorize_error_severity(error) == :critical
    end

    test "categorizes timeouts as medium severity" do
      error = %{type: :timeout, duration_ms: 5000}
      assert ASTErrorHandler.categorize_error_severity(error) == :medium
    end

    test "categorizes unsupported language as low severity" do
      error = %{type: :unsupported_language, language: "cobol"}
      assert ASTErrorHandler.categorize_error_severity(error) == :low
    end

    test "categorizes unknown errors as medium severity" do
      error = %{type: :unknown_error, original_error: %{}}
      assert ASTErrorHandler.categorize_error_severity(error) == :medium
    end
  end

  describe "error_recovery_suggestions/1" do
    test "provides syntax error recovery suggestions" do
      error = %{
        type: :syntax_error,
        message: "Unexpected token ';'",
        language: "javascript"
      }

      suggestions = ASTErrorHandler.error_recovery_suggestions(error)

      assert Enum.any?(suggestions, &String.contains?(&1, "syntax"))
      assert Enum.any?(suggestions, &String.contains?(&1, "semicolon"))
    end

    test "provides timeout recovery suggestions" do
      error = %{type: :timeout, duration_ms: 5000, language: "python"}

      suggestions = ASTErrorHandler.error_recovery_suggestions(error)

      assert Enum.any?(suggestions, &String.contains?(&1, "timeout"))
      assert Enum.any?(suggestions, &(String.contains?(&1, "reduce") or String.contains?(&1, "Reduce")))
    end

    test "provides parser crash recovery suggestions" do
      error = %{
        type: :parser_crash,
        reason: :segmentation_fault,
        language: "php"
      }

      suggestions = ASTErrorHandler.error_recovery_suggestions(error)

      assert Enum.any?(suggestions, &String.contains?(&1, "crash"))
      assert Enum.any?(suggestions, &String.contains?(&1, "fallback"))
    end
  end

  describe "is_recoverable_error?/1" do
    test "syntax errors are recoverable" do
      error = %{type: :syntax_error, message: "Unexpected token"}
      assert ASTErrorHandler.is_recoverable_error?(error) == true
    end

    test "timeouts are recoverable" do
      error = %{type: :timeout, duration_ms: 5000}
      assert ASTErrorHandler.is_recoverable_error?(error) == true
    end

    test "parser crashes are not recoverable" do
      error = %{type: :parser_crash, reason: :segmentation_fault}
      assert ASTErrorHandler.is_recoverable_error?(error) == false
    end

    test "unsupported languages are not recoverable" do
      error = %{type: :unsupported_language, language: "cobol"}
      assert ASTErrorHandler.is_recoverable_error?(error) == false
    end
  end
end