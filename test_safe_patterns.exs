#!/usr/bin/env elixir

# Test script to diagnose safe pattern detection issues

defmodule SafePatternTest do
  alias RsolvWeb.Controllers.Api.V1.SafePatternDetector

  def test_patterns() do
    # Test cases from demo-full-e2e-test.py
    test_cases = [
      # SQL Injection
      %{
        type: :sql_injection,
        language: "javascript",
        safe_code: "const query = 'SELECT * FROM users WHERE id = ?'; // parameterized",
        vulnerable_code: "const query = 'SELECT * FROM users WHERE id = ' + userId;",
        description: "SQL injection with parameterized query"
      },

      # Command Injection
      %{
        type: :command_injection,
        language: "javascript",
        safe_code: "execFile('tar', ['-czf', 'backup.tar.gz', userInput]);",
        vulnerable_code: "exec('tar -czf backup.tar.gz ' + userInput);",
        description: "Command injection with execFile"
      },

      # XSS
      %{
        type: :xss,
        language: "javascript",
        safe_code: "<div><%= userData.bio %></div>",
        vulnerable_code: "<div><%- userData.bio %></div>",
        description: "XSS with EJS escaping"
      },

      # Hardcoded Secret
      %{
        type: :hardcoded_secret,
        language: "javascript",
        safe_code: "const API_KEY = process.env.API_KEY;",
        vulnerable_code: "const API_KEY = 'sk-1234567890abcdef';",
        description: "Hardcoded secret vs environment variable"
      },

      # Path Traversal
      %{
        type: :path_traversal,
        language: "javascript",
        safe_code: "const safePath = path.join(UPLOADS_DIR, path.basename(req.query.filename));",
        vulnerable_code: "fs.readFile(req.query.filename, (err, data) => {",
        description: "Path traversal with sanitization"
      }
    ]

    IO.puts("\n==== Safe Pattern Detection Test Results ====\n")

    Enum.each(test_cases, fn test_case ->
      IO.puts("Testing: #{test_case.description}")
      IO.puts("Type: #{test_case.type}")
      IO.puts("Language: #{test_case.language}")

      # Test safe code
      safe_result =
        SafePatternDetector.is_safe_pattern?(
          test_case.type,
          test_case.safe_code,
          %{language: test_case.language}
        )

      # Test vulnerable code
      vuln_result =
        SafePatternDetector.is_safe_pattern?(
          test_case.type,
          test_case.vulnerable_code,
          %{language: test_case.language}
        )

      IO.puts("Safe code: #{inspect(test_case.safe_code)}")

      IO.puts(
        "  -> Detected as safe: #{safe_result} #{if safe_result, do: "✅", else: "❌ ISSUE!"}"
      )

      IO.puts("Vulnerable code: #{inspect(test_case.vulnerable_code)}")

      IO.puts(
        "  -> Detected as safe: #{vuln_result} #{if !vuln_result, do: "✅", else: "❌ ISSUE!"}"
      )

      IO.puts("")
    end)
  end
end

# Run the tests
SafePatternTest.test_patterns()
