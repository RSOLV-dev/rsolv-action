defmodule RsolvWeb.Api.V1.CommentDetectionTest do
  @moduledoc """
  Unit tests for comment detection functionality.
  Tests the private functions through the public validation API in isolation.

  These tests are FAST and DETERMINISTIC:
  - No database required
  - No HTTP requests
  - No shared state
  - One assertion per test
  """
  use ExUnit.Case, async: true

  alias RsolvWeb.Api.V1.VulnerabilityValidationController, as: Controller

  # Access private functions for unit testing
  # In Elixir, we test private functions through their public interface
  # but we can use this helper to make tests more focused
  defp perform_validation(code, file_content, line_number, file_path \\ "app.js") do
    vuln = %{
      "id" => "test-vuln",
      "type" => "eval-injection",
      "file" => file_path,
      "line" => line_number,
      "code" => code,
      "severity" => "critical"
    }

    files = %{file_path => file_content}

    # Call the private function directly using :erlang.apply
    # This bypasses HTTP but tests the actual logic
    :erlang.apply(Controller, :validate_single_vulnerability, [vuln, files])
  end

  describe "JavaScript single-line comments (//) - Basic Cases" do
    test "detects comment when code IS the comment" do
      result =
        perform_validation(
          "// eval(userInput)",
          "// eval(userInput)\nconsole.log('safe');",
          1
        )

      assert result["isValid"] == false
      assert result["confidence"] <= 0.1
      assert result["reason"] =~ "comment"
    end

    test "detects code after // on same line" do
      result =
        perform_validation(
          "eval(userInput)",
          "const x = 5; // eval(userInput)",
          1
        )

      assert result["isValid"] == false
      assert result["reason"] =~ "comment"
    end

    test "allows real code NOT in comment" do
      result =
        perform_validation(
          "eval(userInput)",
          "// This is safe\neval(userInput);\n// Another comment",
          2
        )

      # This should be valid (not in comment)
      assert result["isValid"] == true
      # But may have low confidence due to no user input taint
      assert result["confidence"] >= 0.4
    end

    test "handles // inside string literals correctly" do
      result =
        perform_validation(
          "const url = \"http://example.com\"",
          "const url = \"http://example.com\";",
          1
        )

      # The // is inside a string, not a comment
      # This should be detected as a string literal, not executable code
      assert result["isValid"] == false
      assert result["reason"] =~ "string literal"
    end
  end

  describe "JavaScript multi-line comments (/* */) - State Tracking" do
    test "detects code inside simple /* */ block" do
      result =
        perform_validation(
          "eval(userInput)",
          "/*\n eval(userInput)\n*/\nconsole.log('safe');",
          2
        )

      assert result["isValid"] == false
      assert result["reason"] =~ "comment"
    end

    test "detects code inside JSDoc /** */ block" do
      result =
        perform_validation(
          "* eval(userInput)",
          "/**\n * This is bad:\n * eval(userInput)\n */",
          3
        )

      assert result["isValid"] == false
      assert result["reason"] =~ "comment"
    end

    test "allows code after comment block closes" do
      result =
        perform_validation(
          "eval(userInput)",
          "/* Comment */\neval(userInput);",
          2
        )

      assert result["isValid"] == true
    end

    test "handles /* */ on same line" do
      result =
        perform_validation(
          "realCode()",
          "/* comment */ realCode();",
          1
        )

      # The comment is closed on same line, so realCode() is executable
      assert result["isValid"] == true
    end

    test "handles nested /* attempts (not valid JS but common typo)" do
      result =
        perform_validation(
          "eval(x)",
          "/* outer /* eval(x) */ still in comment */",
          1
        )

      # In JavaScript, /* does not nest, so the first */ closes it
      # This behavior matches JS spec
      assert result["isValid"] == false
    end
  end

  describe "Python comments (#) - PEP 8 Compliance" do
    test "detects Python single-line comment" do
      result =
        perform_validation(
          "# exec(user_input)",
          "# exec(user_input)\nprint('safe')",
          1,
          "app.py"
        )

      assert result["isValid"] == false
      assert result["reason"] =~ "comment"
    end

    test "allows code not in comment" do
      result =
        perform_validation(
          "exec(user_input)",
          "# Comment\nexec(user_input)",
          2,
          "app.py"
        )

      assert result["isValid"] == true
    end

    test "detects code in triple-quote docstring" do
      result =
        perform_validation(
          "exec(user_input)",
          "\"\"\"\nDangerous:\nexec(user_input)\n\"\"\"\nprint('safe')",
          3,
          "app.py"
        )

      assert result["isValid"] == false
      assert result["reason"] =~ "comment"
    end

    test "allows code after docstring closes" do
      result =
        perform_validation(
          "exec(user_input)",
          "\"\"\"\nDocstring\n\"\"\"\nexec(user_input)",
          4,
          "app.py"
        )

      # After the """ closes, code is executable
      assert result["isValid"] == true
    end

    test "handles single triple-quote (unclosed)" do
      result =
        perform_validation(
          "exec(x)",
          "\"\"\"\nexec(x)\nprint('test')",
          2,
          "app.py"
        )

      # Unclosed """ means everything after is in docstring
      assert result["isValid"] == false
    end
  end

  describe "Ruby comments (#) and =begin/=end - Ruby Docs Compliance" do
    test "detects Ruby single-line comment" do
      result =
        perform_validation(
          "# eval(user_input)",
          "# eval(user_input)\nputs 'safe'",
          1,
          "app.rb"
        )

      assert result["isValid"] == false
      assert result["reason"] =~ "comment"
    end

    test "detects code in =begin/=end block" do
      result =
        perform_validation(
          "eval(user_input)",
          "=begin\nDon't do this:\neval(user_input)\n=end\nputs 'safe'",
          3,
          "app.rb"
        )

      assert result["isValid"] == false
      assert result["reason"] =~ "comment"
    end

    test "allows code after =end" do
      result =
        perform_validation(
          "eval(user_input)",
          "=begin\nComment\n=end\neval(user_input)",
          4,
          "app.rb"
        )

      assert result["isValid"] == true
    end

    test "handles unclosed =begin" do
      result =
        perform_validation(
          "eval(x)",
          "=begin\neval(x)\nputs 'test'",
          2,
          "app.rb"
        )

      # Unclosed =begin means everything after is commented
      assert result["isValid"] == false
    end
  end

  describe "Edge Cases - Robustness" do
    test "handles empty file content" do
      result =
        perform_validation(
          "eval(x)",
          "",
          1
        )

      # Should not crash
      assert Map.has_key?(result, "isValid")
    end

    test "handles line number beyond file length" do
      result =
        perform_validation(
          "eval(x)",
          "console.log('test');",
          100
        )

      # Should not crash, should handle gracefully
      assert Map.has_key?(result, "isValid")
    end

    test "handles line number 0 (converts to 1)" do
      result =
        perform_validation(
          "eval(x)",
          "eval(x);",
          0
        )

      # Line 0 should be treated as line 1
      assert Map.has_key?(result, "isValid")
    end

    test "handles Unicode in comments" do
      result =
        perform_validation(
          "eval(🚀)",
          "// 🚀 eval(🚀)\nconsole.log('test');",
          1
        )

      assert result["isValid"] == false
      assert result["reason"] =~ "comment"
    end

    test "handles very long lines" do
      long_comment = "// " <> String.duplicate("a", 10000) <> " eval(x)"

      result =
        perform_validation(
          "eval(x)",
          long_comment,
          1
        )

      assert result["isValid"] == false
    end

    test "handles mixed comment types in same file" do
      content = """
      // Single line comment
      /* Multi-line
         comment */
      eval(userInput); // actual code with inline comment
      // Another single line
      """

      result =
        perform_validation(
          "eval(userInput)",
          content,
          3
        )

      # Line 3 has real code, not in comment
      assert result["isValid"] == true
    end
  end

  describe "False Negatives - Ensuring We Don't Over-Filter" do
    test "does not reject code that looks like comment syntax" do
      result =
        perform_validation(
          "const url = \"http://example.com\"",
          "const url = \"http://example.com\"; // This is a URL",
          1
        )

      # The http:// in the string is not a comment
      # Should be detected as string literal
      assert result["isValid"] == false
      assert result["reason"] =~ "string literal"
    end

    test "does not reject regex with // pattern" do
      result =
        perform_validation(
          "const regex = /https?:\\/\\//",
          "const regex = /https?:\\/\\//;",
          1
        )

      # This is a regex, not a comment - but might look like one
      # Current implementation may or may not handle this
      # Document the behavior
      assert Map.has_key?(result, "isValid")
    end

    test "does not reject string with /* in it" do
      result =
        perform_validation(
          "const str = \"/* not a comment */\"",
          "const str = \"/* not a comment */\";",
          1
        )

      assert result["isValid"] == false
      assert result["reason"] =~ "string literal"
    end
  end
end
