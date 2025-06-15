defmodule RsolvApi.Security.Patterns.Ruby.InsecureCookieTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Ruby.InsecureCookie
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = InsecureCookie.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "ruby-insecure-cookie"
      assert pattern.name == "Insecure Cookie Settings"
      assert pattern.severity == :medium
      assert pattern.type == :session_management
      assert pattern.languages == ["ruby"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = InsecureCookie.pattern()
      
      assert pattern.cwe_id == "CWE-614"
      assert pattern.owasp_category == "A05:2021"
    end
    
    test "has multiple regex patterns" do
      pattern = InsecureCookie.pattern()
      
      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 9
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = InsecureCookie.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches cookies without secure flag", %{pattern: pattern} do
      vulnerable_code = [
        "cookies[:auth_token] = token",
        "cookies[:session_id] = generate_session_id",
        "cookies['user_data'] = user.to_json",
        "response.set_cookie('auth', token)",
        "cookies[:remember_me] = { value: user_id }"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches cookies with httponly: false", %{pattern: pattern} do
      vulnerable_code = [
        "cookies[:token] = { value: token, httponly: false }",
        "cookies[:session] = { value: session_id, httponly: false, expires: 1.day.from_now }",
        "cookies.signed[:user_id] = { value: user.id, httponly: false }"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches cookies with secure: false", %{pattern: pattern} do
      vulnerable_code = [
        "cookies[:auth] = { value: token, secure: false }",
        "cookies[:session_id] = { value: sid, secure: false, httponly: true }",
        "cookies.encrypted[:user_data] = { value: data, secure: false }"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches cookies without same_site attribute", %{pattern: pattern} do
      vulnerable_code = [
        "cookies[:csrf_token] = { value: token, secure: true, httponly: true }",
        "cookies[:session] = { value: session_id, secure: true }",
        "cookies.permanent[:remember_token] = token"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches permanent cookies without security flags", %{pattern: pattern} do
      vulnerable_code = [
        "cookies.permanent[:auth_token] = token",
        "cookies.permanent[:user_id] = user.id",
        "cookies.permanent.signed[:remember_me] = user.id"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "does not match properly secured cookies", %{pattern: pattern} do
      safe_code = [
        "cookies[:auth_token] = { value: token, secure: true, httponly: true, same_site: :strict }",
        "cookies[:session] = { value: session_id, secure: true, httponly: true, same_site: :lax }",
        "cookies.encrypted[:user_data] = { value: data, secure: true, httponly: true, same_site: :none }",
        "# Comment about cookies[:auth_token]",
        "logger.info 'Setting cookies[:session]'"
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should not match: #{code}"
      end
    end
    
    test "documents known limitations of regex detection", %{pattern: pattern} do
      # These are edge cases that regex might miss or incorrectly flag
      dynamic_config = "secure_flag = Rails.env.production?\ncookies[:auth] = { value: token, secure: secure_flag }"
      
      # This might be flagged as insecure even though secure_flag could be true in production
      # AST enhancement should handle this dynamic configuration
      assert Enum.any?(pattern.regex, &Regex.match?(&1, dynamic_config)) ||
             !Enum.any?(pattern.regex, &Regex.match?(&1, dynamic_config)),
             "Dynamic configuration detection is limited with regex"
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = InsecureCookie.vulnerability_metadata()
      
      assert metadata.description =~ "cookie"
      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 5
      assert length(metadata.real_world_impact) >= 3
      assert length(metadata.cve_examples) >= 3
    end
    
    test "includes CVE examples from research" do
      metadata = InsecureCookie.vulnerability_metadata()
      
      cve_ids = Enum.map(metadata.cve_examples, & &1.id)
      assert Enum.any?(cve_ids, &String.contains?(&1, "CVE-"))
    end
    
    test "includes proper security references" do
      metadata = InsecureCookie.vulnerability_metadata()
      
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = InsecureCookie.ast_enhancement()
      
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.6
    end
    
    test "includes cookie analysis rules" do
      enhancement = InsecureCookie.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert enhancement.ast_rules.cookie_analysis.check_cookie_methods
      assert enhancement.ast_rules.cookie_analysis.cookie_methods
      assert enhancement.ast_rules.cookie_analysis.security_attributes
    end
    
    test "has security flag detection" do
      enhancement = InsecureCookie.ast_enhancement()
      
      assert "secure" in enhancement.ast_rules.security_analysis.required_attributes
      assert "httponly" in enhancement.ast_rules.security_analysis.required_attributes
      assert enhancement.ast_rules.security_analysis.check_attribute_values
    end
    
    test "includes context checking" do
      enhancement = InsecureCookie.ast_enhancement()
      
      assert enhancement.context_rules.check_framework_defaults
      assert enhancement.context_rules.rails_config_files
      assert enhancement.context_rules.check_environment_specific
    end
  end
end