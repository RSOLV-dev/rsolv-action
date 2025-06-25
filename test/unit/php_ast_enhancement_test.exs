defmodule RsolvApi.Unit.PhpAstEnhancementTest do
  use ExUnit.Case, async: true
  
  @moduledoc """
  Unit test to verify PHP pattern AST enhancement returns correct field names.
  This tests the fix for todo #133 where PHP patterns were returning :rules instead of :ast_rules
  """
  
  # Import PHP pattern modules
  alias RsolvApi.Security.Patterns.Php.CommandInjection
  alias RsolvApi.Security.Patterns.Php.SqlInjectionConcat
  alias RsolvApi.Security.Patterns.Php.XssEcho
  alias RsolvApi.Security.Patterns.Php.FileInclusion
  
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
        RsolvApi.Security.Patterns.Php.SqlInjectionInterpolation,
        XssEcho,
        RsolvApi.Security.Patterns.Php.XssPrint,
        FileInclusion,
        RsolvApi.Security.Patterns.Php.FileUploadNoValidation,
        RsolvApi.Security.Patterns.Php.HardcodedCredentials,
        RsolvApi.Security.Patterns.Php.InsecureRandom,
        RsolvApi.Security.Patterns.Php.LdapInjection,
        RsolvApi.Security.Patterns.Php.MissingCsrfToken,
        RsolvApi.Security.Patterns.Php.OpenRedirect,
        RsolvApi.Security.Patterns.Php.PathTraversal,
        RsolvApi.Security.Patterns.Php.RegisterGlobals,
        RsolvApi.Security.Patterns.Php.SessionFixation,
        RsolvApi.Security.Patterns.Php.SsrfVulnerability,
        RsolvApi.Security.Patterns.Php.UnsafeDeserialization,
        RsolvApi.Security.Patterns.Php.WeakCrypto,
        RsolvApi.Security.Patterns.Php.WeakPasswordHash,
        RsolvApi.Security.Patterns.Php.XpathInjection,
        RsolvApi.Security.Patterns.Php.XxeVulnerability,
        RsolvApi.Security.Patterns.Php.EvalUsage,
        RsolvApi.Security.Patterns.Php.ExtractUsage,
        RsolvApi.Security.Patterns.Php.DebugModeEnabled,
        RsolvApi.Security.Patterns.Php.ErrorDisplay
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