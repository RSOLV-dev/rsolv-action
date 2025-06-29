defmodule Mix.Tasks.TestEnhancement do
  use Mix.Task

  @shortdoc "Test if pattern modules have AST enhancement data"
  
  def run(_) do
    # Start the application to load all modules
    Mix.Task.run("app.start")
    
    IO.puts("\n🔍 Testing AST Enhancement Data\n")
    
    # Get all pattern modules
    pattern_modules = [
      RsolvApi.Security.Patterns.Javascript.EvalUserInput,
      RsolvApi.Security.Patterns.Javascript.CommandInjectionExec,
      RsolvApi.Security.Patterns.Javascript.XssInnerHtml,
      RsolvApi.Security.Patterns.Javascript.SqlInjectionConcat,
      RsolvApi.Security.Patterns.Javascript.HardcodedSecretApiKey
    ]
    
    # Check which ones have ast_enhancement/0
    patterns_with_enhancement = Enum.filter(pattern_modules, fn module ->
      Code.ensure_loaded?(module) && function_exported?(module, :ast_enhancement, 0)
    end)
    
    IO.puts("Patterns checked: #{length(pattern_modules)}")
    IO.puts("Patterns with ast_enhancement/0: #{length(patterns_with_enhancement)}")
    
    # Show details for eval pattern
    eval_module = RsolvApi.Security.Patterns.Javascript.EvalUserInput
    
    if Code.ensure_loaded?(eval_module) do
      IO.puts("\n📋 Testing #{eval_module}:")
      IO.puts("Module loaded: ✅")
      
      if function_exported?(eval_module, :pattern, 0) do
        pattern = eval_module.pattern()
        IO.puts("Pattern ID: #{pattern.id}")
        IO.puts("Has pattern/0: ✅")
      end
      
      if function_exported?(eval_module, :ast_enhancement, 0) do
        IO.puts("Has ast_enhancement/0: ✅")
        
        enhancement = eval_module.ast_enhancement()
        IO.puts("\n🌳 AST Rules present: #{map_size(enhancement.ast_rules) > 0}")
        IO.puts("🔧 Context Rules present: #{map_size(enhancement.context_rules) > 0}")
        IO.puts("📊 Confidence Rules present: #{map_size(enhancement.confidence_rules) > 0}")
        IO.puts("Min Confidence: #{enhancement.min_confidence}")
        
        # Show sample data
        IO.puts("\nSample AST rule:")
        IO.inspect(enhancement.ast_rules.node_type, label: "  node_type")
        
        IO.puts("\nSample Context rule:")
        IO.inspect(enhancement.context_rules.exclude_paths, label: "  exclude_paths", limit: 3)
        
        IO.puts("\nSample Confidence adjustments:")
        IO.inspect(Map.keys(enhancement.confidence_rules.adjustments), label: "  adjustment keys")
      else
        IO.puts("Has ast_enhancement/0: ❌")
      end
    else
      IO.puts("\n❌ Could not load #{eval_module}")
    end
  end
end