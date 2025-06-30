defmodule RsolvApi.Security.PatternRegistryTDDTest do
  use ExUnit.Case
  alias RsolvApi.Security.PatternRegistry
  
  describe "TDD: Fix pattern loading issues" do
    # RED PHASE: Write failing tests showing the issues
    
    test "JavaScript patterns should use 'js-' prefix, not 'javascript-'" do
      patterns = PatternRegistry.get_patterns_for_language("javascript")
      sql_pattern = Enum.find(patterns, fn p -> String.contains?(p.id, "sql-injection-concat") end)
      
      assert sql_pattern, "Should find SQL injection pattern"
      # This will fail if test expects "javascript-sql-injection-concat"
      assert sql_pattern.id == "js-sql-injection-concat"
    end
    
    test "PHP patterns should be loaded successfully" do
      patterns = PatternRegistry.get_patterns_for_language("php")
      
      assert length(patterns) > 0, "Should load PHP patterns"
      
      # Check for specific PHP pattern
      xss_pattern = Enum.find(patterns, fn p -> String.contains?(p.id, "xss") && String.contains?(p.id, "echo") end)
      assert xss_pattern, "Should find PHP XSS echo pattern"
    end
    
    test "Common patterns should be loaded and accessible" do
      all_patterns = PatternRegistry.get_all_patterns()
      
      # Check for common patterns that apply across languages
      jwt_patterns = all_patterns |> Enum.filter(fn p -> String.contains?(p.id, "jwt") end)
      hardcoded_patterns = all_patterns |> Enum.filter(fn p -> String.contains?(p.id, "hardcoded") end)
      
      assert length(jwt_patterns) > 0, "Should find JWT-related patterns"
      assert length(hardcoded_patterns) > 0, "Should find hardcoded secret patterns"
    end
    
    test "Pattern loading should work with compiled modules (release mode)" do
      # This test verifies the Application.spec approach works
      case Application.spec(:rsolv_api, :modules) do
        modules when is_list(modules) ->
          pattern_modules = modules
            |> Enum.filter(fn mod ->
              mod_str = to_string(mod)
              String.contains?(mod_str, "RsolvApi.Security.Patterns") &&
              !String.ends_with?(mod_str, "PatternBase")
            end)
          
          # Should find many pattern modules
          assert length(pattern_modules) > 10, "Should find pattern modules via Application.spec"
          
          # Check that they export pattern/0
          valid_patterns = pattern_modules
            |> Enum.filter(&function_exported?(&1, :pattern, 0))
          
          assert length(valid_patterns) > 10, "Pattern modules should export pattern/0"
          
        _ ->
          flunk("Application.spec should return module list")
      end
    end
    
    test "All major languages should have patterns loaded" do
      languages = ["python", "javascript", "ruby", "php", "java", "elixir"]
      
      Enum.each(languages, fn lang ->
        patterns = PatternRegistry.get_patterns_for_language(lang)
        assert length(patterns) > 0, "Should have patterns for #{lang}, but got #{length(patterns)}"
        
        # Also check common patterns are included
        pattern_ids = Enum.map(patterns, & &1.id)
        has_language_specific = Enum.any?(pattern_ids, &String.contains?(&1, lang)) ||
                                Enum.any?(pattern_ids, &String.contains?(&1, String.slice(lang, 0..1)))
        
        assert has_language_specific || lang == "java", 
               "Should have #{lang}-specific patterns in addition to common ones"
      end)
    end
  end
  
  describe "Pattern ID format consistency" do
    test "JavaScript patterns use 'js-' prefix" do
      patterns = PatternRegistry.get_patterns_for_language("javascript")
      js_specific = patterns |> Enum.filter(fn p -> String.starts_with?(p.id, "js-") end)
      
      assert length(js_specific) > 0, "JavaScript patterns should use 'js-' prefix"
    end
    
    test "Python patterns use 'python-' prefix" do
      patterns = PatternRegistry.get_patterns_for_language("python")
      python_specific = patterns |> Enum.filter(fn p -> String.starts_with?(p.id, "python-") end)
      
      assert length(python_specific) > 0, "Python patterns should use 'python-' prefix"
    end
    
    test "PHP patterns use 'php-' prefix" do
      patterns = PatternRegistry.get_patterns_for_language("php")
      php_specific = patterns |> Enum.filter(fn p -> String.starts_with?(p.id, "php-") end)
      
      assert length(php_specific) > 0, "PHP patterns should use 'php-' prefix"
    end
  end
end