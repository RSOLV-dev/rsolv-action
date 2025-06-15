defmodule RsolvApi.Security.Patterns.Ruby.OpenRedirectTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Ruby.OpenRedirect
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = OpenRedirect.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "ruby-open-redirect"
      assert pattern.name == "Open Redirect"
      assert pattern.severity == :medium
      assert pattern.type == :open_redirect
      assert pattern.languages == ["ruby"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = OpenRedirect.pattern()
      
      assert pattern.cwe_id == "CWE-601"
      assert pattern.owasp_category == "A01:2021"
    end
    
    test "has multiple regex patterns" do
      pattern = OpenRedirect.pattern()
      
      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 4
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = OpenRedirect.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches redirect_to with params", %{pattern: pattern} do
      vulnerable_code = [
        "redirect_to params[:return_url]",
        "redirect_to params[:redirect]",
        "redirect_to params['next']",
        "redirect_to request.params[:url]",
        "redirect_to @user_url"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches redirect_to with request.referer", %{pattern: pattern} do
      vulnerable_code = [
        "redirect_to request.referer",
        "redirect_to request.referrer",
        "redirect_to request.env['HTTP_REFERER']",
        "redirect_to request.headers['Referer']"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches redirect_to :back", %{pattern: pattern} do
      vulnerable_code = [
        "redirect_to :back",
        "redirect_to(:back)",
        "redirect_to :back, fallback_location: root_path"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches redirect_back with user input", %{pattern: pattern} do
      vulnerable_code = [
        "redirect_back fallback_location: params[:url]",
        "redirect_back(fallback_location: params[:return])",
        "redirect_back fallback_location: user_provided_url"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches string interpolation in redirect", %{pattern: pattern} do
      vulnerable_code = [
        "redirect_to \"http://\#{params[:host]}/path\"",
        "redirect_to \"https://\#{user_domain}/login\"",
        "redirect_to \"\#{params[:protocol]}://\#{params[:domain]}\"",
        "redirect_to \"//\#{params[:site]}\""
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches URL construction with user input", %{pattern: pattern} do
      vulnerable_code = [
        "url = params[:return_to]\nredirect_to url",
        "redirect_url = request.params[:next]\nredirect_to redirect_url",
        "target = user.redirect_url\nredirect_to target"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe redirects", %{pattern: pattern} do
      safe_code = [
        "redirect_to root_path",
        "redirect_to login_url",
        "redirect_to dashboard_path",
        "redirect_to action: 'index'",
        "redirect_to controller: 'users', action: 'show'",
        "redirect_back fallback_location: root_path"
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should not match: #{code}"
      end
    end
    
    test "documents known limitations of regex detection", %{pattern: pattern} do
      # These are false positives that regex will match but AST enhancement should filter
      validation_wrapped_code = "safe_urls = [root_path, dashboard_path]\nif safe_urls.include?(params[:return_url])\n  redirect_to params[:return_url]\nend"
      
      # This is expected to match with regex (AST enhancement handles the false positive)
      assert Enum.any?(pattern.regex, &Regex.match?(&1, validation_wrapped_code)),
             "Regex is expected to match validated redirects (AST enhancement filters these)"
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = OpenRedirect.vulnerability_metadata()
      
      assert metadata.description =~ "Open redirect"
      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 5
      assert length(metadata.real_world_impact) >= 3
      assert length(metadata.cve_examples) >= 4
    end
    
    test "includes CVE examples from research" do
      metadata = OpenRedirect.vulnerability_metadata()
      
      cve_ids = Enum.map(metadata.cve_examples, & &1.id)
      assert Enum.any?(cve_ids, &String.contains?(&1, "CVE-2023-22797"))
      assert Enum.any?(cve_ids, &String.contains?(&1, "CVE-2021-22903"))
      assert Enum.any?(cve_ids, &String.contains?(&1, "CVE-2021-22942"))
      assert Enum.any?(cve_ids, &String.contains?(&1, "CVE-2023-28362"))
    end
    
    test "includes proper security references" do
      metadata = OpenRedirect.vulnerability_metadata()
      
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = OpenRedirect.ast_enhancement()
      
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.6
    end
    
    test "includes redirect method analysis" do
      enhancement = OpenRedirect.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert enhancement.ast_rules.redirect_analysis.check_redirect_methods
      assert enhancement.ast_rules.redirect_analysis.redirect_methods
      assert enhancement.ast_rules.redirect_analysis.dangerous_sources
    end
    
    test "has user input detection" do
      enhancement = OpenRedirect.ast_enhancement()
      
      assert "params" in enhancement.ast_rules.user_input_analysis.input_sources
      assert "request" in enhancement.ast_rules.user_input_analysis.input_sources
      assert enhancement.ast_rules.user_input_analysis.check_url_construction
    end
    
    test "includes URL validation checks" do
      enhancement = OpenRedirect.ast_enhancement()
      
      assert enhancement.ast_rules.validation_analysis.check_url_validation
      assert enhancement.ast_rules.validation_analysis.safe_redirect_patterns
      assert enhancement.ast_rules.validation_analysis.validation_methods
    end
  end
end