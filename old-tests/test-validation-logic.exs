#!/usr/bin/env elixir

# Test the SafePatternDetector logic locally
Code.require_file("lib/rsolv_web/controllers/api/v1/safe_pattern_detector.ex")

alias RsolvWeb.Api.V1.SafePatternDetector

# Test cases
test_cases = [
  {:sql_injection, "db.query(\"SELECT * FROM users WHERE id = \" + req.params.id)", "javascript"},
  {:sql_injection, "db.query(\"SELECT * FROM users WHERE id = $1\", [req.params.id])", "javascript"},
  {:sql_injection, "db.query(\"SELECT * FROM users WHERE id = 1\")", "javascript"},
  {:xss, "element.innerHTML = userContent", "javascript"},
  {:xss, "element.textContent = userContent", "javascript"},
  {:command_injection, "exec(\"convert \" + req.body.filename + \" output.pdf\")", "javascript"},
  {:command_injection, "exec(\"npm run build\")", "javascript"},
]

IO.puts("Testing SafePatternDetector logic:")
IO.puts("===================================\n")

for {vuln_type, code, language} <- test_cases do
  result = SafePatternDetector.is_safe_pattern?(vuln_type, code, %{language: language})
  
  IO.puts("Type: #{vuln_type}")
  IO.puts("Code: #{code}")
  IO.puts("Language: #{language}")
  IO.puts("Is Safe? #{result}")
  
  if function_exported?(SafePatternDetector, :explain_safety, 3) do
    explanation = SafePatternDetector.explain_safety(vuln_type, code, %{language: language})
    IO.puts("Explanation: #{explanation}")
  end
  
  IO.puts("---\n")
end