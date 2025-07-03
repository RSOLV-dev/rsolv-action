defmodule Rsolv.Unit.PhpAstEnhancementTest do
  use ExUnit.Case, async: true
  
  @moduledoc """
  Unit test to verify PHP pattern AST enhancement returns correct field names.
  This tests the fix for todo #133 where PHP patterns were returning :rules instead of :ast_rules
  """
  
  # Import PHP pattern modules
  alias Rsolv.Security.Patterns.Php.CommandInjection
  alias Rsolv.Security.Patterns.Php.SqlInjectionConcat
  alias Rsolv.Security.Patterns.Php.XssEcho
  alias Rsolv.Security.Patterns.Php.FileInclusion
  
  describe "PHP pattern AST enhancement field names" do
    test "command injection pattern returns ast_rules not rules" do
      enhancement = CommandInjection.ast_enhancement()
      
      # Should have ast_rules key
      assert Map.has_key?(enhancement, :ast_rules)
      
      # Should NOT have rules key
      refute Map.has_key?(enhancement, :rules)
      
      # ast_rules should be a list
      assert is_list(enhancement.ast_rules)
      assert length(enhancement.ast_rules) > 0
      
      # Should have min_confidence
      assert Map.has_key?(enhancement, :min_confidence)
      assert is_float(enhancement.min_confidence)
    end
    
    test "SQL injection pattern returns ast_rules" do
      enhancement = SqlInjectionConcat.ast_enhancement()
      
      assert Map.has_key?(enhancement, :ast_rules)
      refute Map.has_key?(enhancement, :rules)
      assert is_list(enhancement.ast_rules)
    end
    
    test "XSS echo pattern returns ast_rules" do
      enhancement = XssEcho.ast_enhancement()
      
      assert Map.has_key?(enhancement, :ast_rules)
      refute Map.has_key?(enhancement, :rules)
      assert is_list(enhancement.ast_rules)
    end
    
    test "file inclusion pattern returns ast_rules" do
      enhancement = FileInclusion.ast_enhancement()
      
      assert Map.has_key?(enhancement, :ast_rules)
      refute Map.has_key?(enhancement, :rules)
      assert is_list(enhancement.ast_rules)
    end
    
    test "all PHP patterns with AST enhancement use correct field names" do
      # List of all PHP pattern modules with AST enhancement
      pattern_modules = [
        CommandInjection,
        SqlInjectionConcat,
        Rsolv.Security.Patterns.Php.SqlInjectionInterpolation,
        XssEcho,
        Rsolv.Security.Patterns.Php.XssPrint,
        FileInclusion,
        Rsolv.Security.Patterns.Php.FileUploadNoValidation,
        Rsolv.Security.Patterns.Php.HardcodedCredentials,
        Rsolv.Security.Patterns.Php.InsecureRandom,
        Rsolv.Security.Patterns.Php.LdapInjection,
        Rsolv.Security.Patterns.Php.MissingCsrfToken,
        Rsolv.Security.Patterns.Php.OpenRedirect,
        Rsolv.Security.Patterns.Php.PathTraversal,
        Rsolv.Security.Patterns.Php.RegisterGlobals,
        Rsolv.Security.Patterns.Php.SessionFixation,
        Rsolv.Security.Patterns.Php.SsrfVulnerability,
        Rsolv.Security.Patterns.Php.UnsafeDeserialization,
        Rsolv.Security.Patterns.Php.WeakCrypto,
        Rsolv.Security.Patterns.Php.WeakPasswordHash,
        Rsolv.Security.Patterns.Php.XpathInjection,
        Rsolv.Security.Patterns.Php.XxeVulnerability,
        Rsolv.Security.Patterns.Php.EvalUsage,
        Rsolv.Security.Patterns.Php.ExtractUsage,
        Rsolv.Security.Patterns.Php.DebugModeEnabled,
        Rsolv.Security.Patterns.Php.ErrorDisplay
      ]
      
      Enum.each(pattern_modules, fn module ->
        if function_exported?(module, :ast_enhancement, 0) do
          enhancement = apply(module, :ast_enhancement, [])
          
          assert Map.has_key?(enhancement, :ast_rules), 
                 "Module #{inspect(module)} should have :ast_rules key"
                 
          refute Map.has_key?(enhancement, :rules), 
                 "Module #{inspect(module)} should NOT have :rules key"
                 
          assert is_list(enhancement.ast_rules) || is_map(enhancement.ast_rules),
                 "Module #{inspect(module)} ast_rules should be list or map"
        end
      end)
    end
  end
end