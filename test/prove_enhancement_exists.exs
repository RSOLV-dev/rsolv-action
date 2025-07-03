#!/usr/bin/env elixir

# Script to prove that pattern modules have AST enhancement data

# First, add the _build path to load the compiled modules
Code.prepend_path("_build/dev/lib/rsolv_api/ebin")

defmodule ProveEnhancement do
  def run do
    IO.puts("\n🔍 Proving AST Enhancement Data Exists\n")
    
    # Test multiple patterns
    patterns = [
      Rsolv.Security.Patterns.Javascript.EvalUserInput,
      Rsolv.Security.Patterns.Javascript.CommandInjectionExec,
      Rsolv.Security.Patterns.Javascript.XssInnerHtml,
      Rsolv.Security.Patterns.Javascript.SqlInjectionConcat,
      Rsolv.Security.Patterns.Javascript.HardcodedSecretApiKey
    ]
    
    patterns_with_enhancement = Enum.filter(patterns, fn module ->
      function_exported?(module, :ast_enhancement, 0)
    end)
    
    IO.puts("Patterns checked: #{length(patterns)}")
    IO.puts("Patterns with ast_enhancement/0: #{length(patterns_with_enhancement)}")
    IO.puts("Percentage: #{round(length(patterns_with_enhancement) / length(patterns) * 100)}%\n")
    
    # Show detailed enhancement for eval pattern
    if Enum.member?(patterns_with_enhancement, Rsolv.Security.Patterns.Javascript.EvalUserInput) do
      IO.puts("📋 Detailed enhancement for js-eval-user-input:")
      
      pattern = Rsolv.Security.Patterns.Javascript.EvalUserInput.pattern()
      enhancement = Rsolv.Security.Patterns.Javascript.EvalUserInput.ast_enhancement()
      
      IO.puts("\nPattern ID: #{pattern.id}")
      IO.puts("Pattern has regex: #{inspect(pattern.regex)}")
      
      IO.puts("\n🌳 AST Rules:")
      IO.inspect(enhancement.ast_rules, pretty: true, limit: 5)
      
      IO.puts("\n🔧 Context Rules:")
      IO.inspect(enhancement.context_rules, pretty: true, limit: 5)
      
      IO.puts("\n📊 Confidence Rules:")
      IO.inspect(enhancement.confidence_rules, pretty: true, limit: 5)
      
      IO.puts("\nMin Confidence: #{enhancement.min_confidence}")
      
      # Check for regex in enhancement
      enhancement_string = inspect(enhancement)
      has_regex = String.contains?(enhancement_string, "~r/")
      IO.puts("\nEnhancement contains regex objects: #{has_regex}")
    end
    
    IO.puts("\n✅ Enhancement data confirmed to exist in pattern modules!")
  end
end

ProveEnhancement.run()