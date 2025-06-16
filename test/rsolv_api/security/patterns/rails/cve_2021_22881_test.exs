defmodule RsolvApi.Security.Patterns.Rails.Cve202122881Test do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Rails.Cve202122881
  alias RsolvApi.Security.Pattern

  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = Cve202122881.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "rails-cve-2021-22881"
      assert pattern.name == "CVE-2021-22881 - Host Authorization Open Redirect"
      assert pattern.type == :open_redirect
      assert pattern.severity == :medium
      assert pattern.languages == ["ruby"]
      assert pattern.frameworks == ["rails"]
      assert pattern.cwe_id == "CWE-601"
      assert pattern.owasp_category == "A01:2021"
    end

    test "has valid regex patterns" do
      pattern = Cve202122881.pattern()
      
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
      Enum.each(pattern.regex, fn regex -> assert %Regex{} = regex end)
    end

    test "has test cases" do
      pattern = Cve202122881.pattern()
      
      assert %{vulnerable: vulnerable, safe: safe} = pattern.test_cases
      assert is_list(vulnerable) and length(vulnerable) > 0
      assert is_list(safe) and length(safe) > 0
    end
  end

  describe "vulnerability detection" do
    test "detects host header injection via redirect_to" do
      pattern = Cve202122881.pattern()
      
      vulnerable_code = [
        "redirect_to request.protocol + request.host + \"/path\"",
        "redirect_to \"\\#\{request.protocol\}\\#\{request.host\}/callback\"",
        "redirect_to \"\\#\{request.protocol\}//\\#\{request.host\}/path\"",
        "redirect_to \"https://\" + request.host + path",
        "redirect_to request.url",
        "redirect_to request.original_url"
      ]
      
      Enum.each(vulnerable_code, fn code ->
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end)
    end

    test "detects host header injection via url_for" do
      pattern = Cve202122881.pattern()
      
      vulnerable_code = [
        "url_for(host: request.host, path: params[:path])",
        "url_for(host: request.host_with_port, action: params[:action])",
        "url_for(host: request.host, controller: 'home', action: params[:redirect])"
      ]
      
      Enum.each(vulnerable_code, fn code ->
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end)
    end

    test "detects host authorization middleware bypass" do
      pattern = Cve202122881.pattern()
      
      vulnerable_code = [
        "config.hosts << \".\#{params[:domain]}\"",
        "config.hosts = [\"\#{request.host}\"]",
        "Rails.application.config.hosts << request.host"
      ]
      
      Enum.each(vulnerable_code, fn code ->
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end)
    end

    test "detects Host header manipulation patterns" do
      pattern = Cve202122881.pattern()
      
      vulnerable_code = [
        "Host: evil.com",
        "X-Forwarded-Host: attacker.com", 
        "redirect_to root_url(host: params[:host])",
        "redirect_to url_for(host: params[:redirect_host])"
      ]
      
      Enum.each(vulnerable_code, fn code ->
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end)
    end
  end

  describe "safe code validation" do
    test "does not detect safe redirect patterns" do
      pattern = Cve202122881.pattern()
      
      safe_code = [
        "redirect_to root_url",
        "redirect_to '/dashboard'",
        "redirect_to home_path",
        "redirect_to user_profile_url(user)",
        "redirect_to 'https://example.com/callback'",
        "url_for(action: 'show', id: params[:id])",
        "config.hosts = ['example.com', 'www.example.com']"
      ]
      
      Enum.each(safe_code, fn code ->
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "False positive for: #{code}"
      end)
    end

    test "does not detect commented code" do
      pattern = Cve202122881.pattern()
      
      commented_code = [
        "# redirect_to request.protocol + request.host + \"/path\"",
        "  # redirect_to request.url",
        "// redirect_to url_for(host: request.host)"
      ]
      
      Enum.each(commented_code, fn code ->
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "False positive for commented code: #{code}"
      end)
    end

    test "does not detect safe host configurations" do
      pattern = Cve202122881.pattern()
      
      safe_code = [
        "config.hosts = ['localhost', '127.0.0.1']",
        "Rails.application.config.hosts << 'example.com'",
        "config.force_ssl = true"
      ]
      
      Enum.each(safe_code, fn code ->
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "False positive for: #{code}"
      end)
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive vulnerability metadata" do
      metadata = Cve202122881.vulnerability_metadata()
      
      assert is_binary(metadata.description)
      assert String.contains?(metadata.description, "Host Authorization")
      assert String.contains?(metadata.description, "open redirect")
      
      assert is_list(metadata.references)
      assert length(metadata.references) >= 2
      
      # Check for CVE reference
      assert Enum.any?(metadata.references, fn ref ->
        ref.type == :cve and ref.id == "CVE-2021-22881"
      end)
      
      # Check for CWE reference  
      assert Enum.any?(metadata.references, fn ref ->
        ref.type == :cwe and ref.id == "CWE-601"
      end)
      
      assert is_list(metadata.attack_vectors)
      assert length(metadata.attack_vectors) >= 3
      
      assert is_list(metadata.real_world_impact)
      assert length(metadata.real_world_impact) >= 2
      
      assert is_list(metadata.cve_examples)
      assert length(metadata.cve_examples) >= 1
      
      assert is_list(metadata.safe_alternatives)
      assert length(metadata.safe_alternatives) >= 3
    end

    test "includes CVE-2021-22881 specific information" do
      metadata = Cve202122881.vulnerability_metadata()
      
      cve_example = Enum.find(metadata.cve_examples, &(&1.id == "CVE-2021-22881"))
      assert cve_example
      assert cve_example.severity == "medium"
      assert cve_example.cvss == 6.1
      assert String.contains?(cve_example.description, "Host Authorization")
    end
  end

  describe "ast_enhancement/0" do
    test "returns valid AST enhancement structure" do
      enhancement = Cve202122881.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.0
      assert enhancement.min_confidence <= 1.0
    end

    test "includes redirect-specific AST rules" do
      enhancement = Cve202122881.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert is_list(enhancement.ast_rules.redirect_analysis.redirect_methods)
      assert "redirect_to" in enhancement.ast_rules.redirect_analysis.redirect_methods
    end

    test "includes host validation rules" do
      enhancement = Cve202122881.ast_enhancement()
      
      assert is_list(enhancement.context_rules.exclude_patterns)
      assert enhancement.context_rules.check_host_validation == true
      assert is_list(enhancement.context_rules.safe_host_patterns)
    end

    test "has confidence adjustments for open redirect detection" do
      enhancement = Cve202122881.ast_enhancement()
      
      adjustments = enhancement.confidence_rules.adjustments
      assert is_map(adjustments)
      assert Map.has_key?(adjustments, "uses_request_host")
      assert Map.has_key?(adjustments, "has_host_validation")
    end
  end

  describe "file applicability" do
    test "applies to Rails controller files" do
      assert Cve202122881.applies_to_file?("app/controllers/application_controller.rb")
      assert Cve202122881.applies_to_file?("app/controllers/users_controller.rb")
      assert Cve202122881.applies_to_file?("lib/controllers/api_controller.rb")
    end

    test "applies to Rails configuration files" do
      assert Cve202122881.applies_to_file?("config/application.rb")
      assert Cve202122881.applies_to_file?("config/environments/production.rb")
      assert Cve202122881.applies_to_file?("config/environments/development.rb")
    end

    test "applies to Rails middleware files" do
      assert Cve202122881.applies_to_file?("app/middleware/host_authorization.rb")
      assert Cve202122881.applies_to_file?("lib/middleware/custom_host_auth.rb")
    end

    test "does not apply to non-Rails files" do
      refute Cve202122881.applies_to_file?("package.json")
      refute Cve202122881.applies_to_file?("Dockerfile")
      refute Cve202122881.applies_to_file?("README.md")
      refute Cve202122881.applies_to_file?("spec/javascript/test.js")
    end

    test "does not apply to view files" do
      refute Cve202122881.applies_to_file?("app/views/users/show.html.erb")
      refute Cve202122881.applies_to_file?("app/views/layouts/application.html.erb")
    end
  end
end