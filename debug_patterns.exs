#!/usr/bin/env elixir

# Quick debug script to check what patterns are returned
patterns = RsolvApi.Security.ASTPattern.get_patterns("javascript", :public, :standard)
pattern_ids = Enum.map(patterns, & &1.id)

IO.puts("Number of patterns: #{length(patterns)}")
IO.puts("Pattern IDs:")
IO.inspect(pattern_ids, label: "Pattern IDs")

IO.puts("\nExpected patterns from test:")
expected = [
  "js-sql-injection-concat",
  "js-sql-injection-interpolation", 
  "js-xss-innerhtml",
  "js-xss-document-write",
  "js-command-injection-exec"
]

IO.inspect(expected, label: "Expected")

IO.puts("\nMissing patterns:")
missing = expected -- pattern_ids
IO.inspect(missing, label: "Missing")

IO.puts("\nExtra patterns:")
extra = pattern_ids -- expected
IO.inspect(extra, label: "Extra")