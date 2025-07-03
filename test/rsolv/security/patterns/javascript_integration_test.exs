defmodule Rsolv.Security.Patterns.JavascriptIntegrationTest do
  use ExUnit.Case, async: true
  
  alias Rsolv.Security.Patterns.Javascript
  alias Rsolv.Security.Pattern
  
  describe "Javascript.all/0 integration with new pattern modules" do
    test "returns patterns from new pattern modules" do
      patterns = Javascript.all()
      
      # Should return Pattern structs
      assert Enum.all?(patterns, &match?(%Pattern{}, &1))
      
      # Should include our migrated patterns
      pattern_ids = Enum.map(patterns, & &1.id)
      assert "js-sql-injection-concat" in pattern_ids
      assert "js-sql-injection-interpolation" in pattern_ids
      assert "js-xss-innerhtml" in pattern_ids
      assert "js-xss-document-write" in pattern_ids
      assert "js-command-injection-exec" in pattern_ids
    end
    
    test "sql_injection_concat returns pattern from new module" do
      pattern = Javascript.sql_injection_concat()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-sql-injection-concat"
      assert pattern.name == "SQL Injection via String Concatenation"
      assert pattern.type == :sql_injection
      assert pattern.severity == :critical
    end
    
    test "xss_innerhtml returns pattern from new module" do
      pattern = Javascript.xss_innerhtml()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-xss-innerhtml"
      assert pattern.name == "Cross-Site Scripting (XSS) via innerHTML"
      assert pattern.type == :xss
      assert pattern.severity == :high
    end
    
    test "patterns have consistent API format" do
      pattern = Javascript.command_injection_exec()
      api_format = Pattern.to_api_format(pattern)
      
      # Check expected API format fields
      assert Map.has_key?(api_format, :id)
      assert Map.has_key?(api_format, :name)
      assert Map.has_key?(api_format, :type)
      assert Map.has_key?(api_format, :severity)
      assert Map.has_key?(api_format, :languages)
      assert Map.has_key?(api_format, :regex_patterns)
      assert Map.has_key?(api_format, :examples)
      
      # Check types
      assert is_binary(api_format.type)
      assert is_binary(api_format.severity)
      assert is_list(api_format.regex_patterns)
      assert is_map(api_format.examples)
      assert Map.has_key?(api_format.examples, :vulnerable)
      assert Map.has_key?(api_format.examples, :safe)
    end
  end
  
  describe "pattern module functions work correctly" do
    test "SqlInjectionConcat module functions can be called" do
      module = Rsolv.Security.Patterns.Javascript.SqlInjectionConcat
      
      # Test that functions can actually be called successfully
      assert %Pattern{} = module.pattern()
      assert is_map(module.vulnerability_metadata())
      assert is_boolean(module.applies_to_file?("test.js", nil))
      assert is_boolean(module.applies_to_file?("test.js", "content"))
    end
    
    test "XssInnerhtml module functions can be called" do
      module = Rsolv.Security.Patterns.Javascript.XssInnerhtml
      
      # Test that functions can actually be called successfully
      assert %Pattern{} = module.pattern()
      assert is_map(module.vulnerability_metadata())
      assert is_boolean(module.applies_to_file?("test.js", nil))
      assert is_boolean(module.applies_to_file?("test.js", "content"))
    end
  end
end