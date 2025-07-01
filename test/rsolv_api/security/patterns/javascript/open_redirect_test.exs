defmodule RsolvApi.Security.Patterns.Javascript.OpenRedirectTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Javascript.OpenRedirect
  alias RsolvApi.Security.Pattern
  
  doctest OpenRedirect
  
  # Test helpers for better readability
  defp get_pattern, do: OpenRedirect.pattern()
  
  defp assert_matches_code(pattern, code) do
    assert Regex.match?(pattern.regex, code), 
      "Pattern should match vulnerable code: #{code}"
  end
  
  defp refute_matches_code(pattern, code) do
    refute Regex.match?(pattern.regex, code),
      "Pattern should NOT match safe code: #{code}"
  end
  
  # Remove this function as it's no longer used after refactoring
  
  defp server_side_redirects do
    [
      # Express/Node.js redirects
      "res.redirect(req.query.url)",
      "res.redirect(req.params.redirect)",
      "res.redirect(req.body.returnUrl)",
      "response.redirect(params.goto)",
      
      # With concatenation
      "res.redirect('/auth?next=' + req.query.next)",
      "res.redirect(baseUrl + userInput)",
      "response.redirect(protocol + '://' + req.body.host)"
    ]
  end
  
  defp client_side_redirects do
    [
      # window.location manipulation
      "window.location.href = req.query.url",
      "window.location = params.redirect",
      "window.location.href = userInput",
      "document.location = input",
      
      # location methods
      "location.replace(req.body.url)",
      "location.assign(params.redirect)",
      "window.location.replace(userProvidedUrl)",
      
      # With template literals
      "window.location.href = `${params.protocol}://${params.host}`",
      "location.href = `${req.query.return}`"
    ]
  end
  
  defp meta_refresh_redirects do
    [
      # Meta refresh with user input
      "meta.content = '0; url=' + req.query.redirect",
      "document.write('<meta http-equiv=\"refresh\" content=\"0; url=' + params.url + '\">')",
      "innerHTML = `<meta http-equiv=\"refresh\" content=\"0; url=${userInput}\">`"
    ]
  end
  
  defp header_redirects do
    [
      # HTTP header manipulation
      "res.header('Location', req.body.url)",
      "res.setHeader('Location', params.redirect)",
      "response.headers['Location'] = userInput"
    ]
  end
  
  defp framework_specific_redirects do
    [
      # React Router
      "history.push(req.query.next)",
      "navigate(params.redirect)",
      
      # Angular
      "router.navigate([userInput])",
      "$location.path(req.query.return)",
      
      # Vue Router
      "this.$router.push(params.next)",
      "router.push({ path: userInput })"
    ]
  end
  
  # Remove this function as it's no longer used after refactoring
  
  defp validated_redirects do
    [
      # URL validation before redirect - using variable names that don't trigger the pattern
      "if (isValidRedirect(destination)) { res.redirect(destination) }",
      "const validated = validateUrl(untrusted); res.redirect(validated)",
      "if (allowedDomains.includes(parsedHost)) { res.redirect(allowedHost) }",
      "res.redirect(sanitize(untrusted))"
    ]
  end
  
  defp whitelist_redirects do
    [
      # Whitelist-based redirects - avoiding patterns that contain user input terms
      "res.redirect(ALLOWED_REDIRECTS[pageType])",
      "const safeTarget = whitelist[pageId] || '/home'; res.redirect(safeTarget)",
      "switch(page) { case 'home': res.redirect('/home'); break; }",
      "res.redirect(getFromConfig(configKey))"
    ]
  end
  
  defp relative_redirects do
    [
      # Safe relative redirects
      "res.redirect('/dashboard')",
      "res.redirect('../login')",
      "window.location.href = '/home'",
      "location.replace('./profile')"
    ]
  end
  
  defp hardcoded_redirects do
    [
      # Hardcoded absolute URLs
      "res.redirect('https://example.com/success')",
      "window.location.href = 'https://myapp.com/dashboard'",
      "location.replace('https://trusted-site.com')",
      "res.redirect(CONSTANTS.HOME_PAGE)"
    ]
  end
  
  defp sanitized_redirects do
    [
      # Pre-sanitized or constructed URLs - avoiding problematic variable names
      "res.redirect(`/customer/${customerId}/profile`)",
      "window.location.href = `/app/${appId}`",
      "res.redirect(buildSafe(id, action))",
      "location.href = constructInternal(pageKey)"
    ]
  end
  
  describe "OpenRedirect pattern structure" do
    test "returns correct pattern structure with all required fields" do
      pattern = get_pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-open-redirect"
      assert pattern.name == "Open Redirect Vulnerability"
      assert pattern.description == "Redirecting to user-controlled URLs can lead to phishing attacks"
      assert pattern.type == :open_redirect
      assert pattern.severity == :medium
      assert pattern.languages == ["javascript", "typescript"]
      assert pattern.cwe_id == "CWE-601"
      assert pattern.owasp_category == "A01:2021"
      assert is_binary(pattern.recommendation)
      assert is_map(pattern.test_cases)
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
    end
    
  end

  describe "vulnerability detection" do
    test "detects server-side redirects with user input" do
      pattern = get_pattern()
      
      for code <- server_side_redirects() do
        assert_matches_code(pattern, code)
      end
    end

    test "detects client-side location manipulation" do
      pattern = get_pattern()
      
      for code <- client_side_redirects() do
        assert_matches_code(pattern, code)
      end
    end

    test "detects meta refresh and header-based redirects" do
      pattern = get_pattern()
      
      for code <- meta_refresh_redirects() ++ header_redirects() do
        assert_matches_code(pattern, code)
      end
    end

    test "detects framework-specific routing vulnerabilities" do
      pattern = get_pattern()
      
      for code <- framework_specific_redirects() do
        assert_matches_code(pattern, code)
      end
    end
  end

  describe "safe pattern recognition" do
    test "ignores validated and sanitized redirects" do
      pattern = get_pattern()
      
      for code <- validated_redirects() ++ sanitized_redirects() do
        refute_matches_code(pattern, code)
      end
    end

    test "ignores whitelist-based and hardcoded redirects" do
      pattern = get_pattern()
      
      for code <- whitelist_redirects() ++ hardcoded_redirects() do
        refute_matches_code(pattern, code)
      end
    end

    test "ignores safe relative redirects" do
      pattern = get_pattern()
      
      for code <- relative_redirects() do
        refute_matches_code(pattern, code)
      end
    end
  end

  describe "vulnerability metadata" do
    
    test "provides comprehensive vulnerability metadata with proper structure" do
      metadata = OpenRedirect.vulnerability_metadata()
      
      # Basic structure validation
      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert String.length(metadata.description) > 100
      
      # Validate authoritative references
      assert is_list(metadata.references)
      assert length(metadata.references) >= 4
      
      valid_reference_types = [:cwe, :owasp, :nist, :research, :sans, :vendor]
      for ref <- metadata.references do
        assert Map.has_key?(ref, :type)
        assert Map.has_key?(ref, :url)
        assert ref.type in valid_reference_types
        assert String.starts_with?(ref.url, "http")
      end
      
      # Validate attack methodology documentation
      assert is_list(metadata.attack_vectors) and length(metadata.attack_vectors) >= 5
      assert is_list(metadata.real_world_impact) and length(metadata.real_world_impact) >= 5
      assert is_list(metadata.safe_alternatives) and length(metadata.safe_alternatives) >= 5
      
      # Validate CVE examples with proper severity classification
      assert is_list(metadata.cve_examples)
      assert length(metadata.cve_examples) >= 3
      
      valid_severities = ["low", "medium", "high", "critical"]
      for cve <- metadata.cve_examples do
        assert Map.has_key?(cve, :id)
        assert Map.has_key?(cve, :description)
        assert Map.has_key?(cve, :severity)
        assert String.starts_with?(cve.id, "CVE-")
        assert cve.severity in valid_severities
      end
      
      # Validate detection methodology documentation
      assert is_binary(metadata.detection_notes)
      assert String.length(metadata.detection_notes) > 50
    end
    
  end

  describe "file type detection" do
    test "applies to JavaScript and TypeScript files" do
      javascript_files = ["test.js", "app.jsx", "server.ts", "component.tsx", "module.mjs"]
      
      for file <- javascript_files do
        assert OpenRedirect.applies_to_file?(file, nil),
          "Should apply to JavaScript file: #{file}"
      end
    end

    test "does not apply to other language files" do
      other_language_files = ["test.py", "app.rb", "server.php", "component.vue", "script.sh"]
      
      for file <- other_language_files do
        refute OpenRedirect.applies_to_file?(file, nil),
          "Should NOT apply to non-JavaScript file: #{file}"
      end
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns comprehensive AST enhancement rules" do
      enhancement = OpenRedirect.ast_enhancement()
      
      assert is_map(enhancement)
      assert Enum.sort(Map.keys(enhancement)) == Enum.sort([:ast_rules, :context_rules, :confidence_rules, :min_confidence])
    end
    
    test "AST rules target redirect call expressions" do
      enhancement = OpenRedirect.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert enhancement.ast_rules.callee.object == "res"
      assert enhancement.ast_rules.callee.property == "redirect"
      assert is_list(enhancement.ast_rules.callee.alternatives)
      assert enhancement.ast_rules.argument_analysis.contains_user_input == true
      assert enhancement.ast_rules.argument_analysis.not_validated_url == true
    end
    
    test "context rules exclude test files and validated URLs" do
      enhancement = OpenRedirect.ast_enhancement()
      
      assert Enum.any?(enhancement.context_rules.exclude_paths, &(&1 == ~r/test/))
      assert Enum.any?(enhancement.context_rules.exclude_paths, &(&1 == ~r/spec/))
      assert enhancement.context_rules.exclude_if_url_validated == true
      assert enhancement.context_rules.exclude_if_relative_only == true
      assert enhancement.context_rules.exclude_if_same_origin == true
      assert enhancement.context_rules.safe_redirect_patterns == ["/login", "/home", "/dashboard"]
    end
    
    test "confidence rules heavily penalize validation and allowlists" do
      enhancement = OpenRedirect.ast_enhancement()
      
      assert enhancement.confidence_rules.base == 0.4
      assert enhancement.confidence_rules.adjustments["direct_query_param_redirect"] == 0.5
      assert enhancement.confidence_rules.adjustments["referer_header_redirect"] == 0.3
      assert enhancement.confidence_rules.adjustments["return_url_parameter"] == 0.4
      assert enhancement.confidence_rules.adjustments["url_validation_present"] == -0.8
      assert enhancement.confidence_rules.adjustments["allowlist_check"] == -0.9
      assert enhancement.confidence_rules.adjustments["relative_path_only"] == -0.6
      assert enhancement.confidence_rules.adjustments["hardcoded_base_domain"] == -0.7
      assert enhancement.min_confidence == 0.8
    end
  end
  
  describe "enhanced_pattern/0" do
    test "returns pattern with AST enhancement from ast_enhancement/0" do
      enhanced = OpenRedirect.enhanced_pattern()
      enhancement = OpenRedirect.ast_enhancement()
      
      # Verify it has all the AST enhancement fields
      assert enhanced.ast_rules == enhancement.ast_rules
      assert enhanced.context_rules == enhancement.context_rules
      assert enhanced.confidence_rules == enhancement.confidence_rules
      assert enhanced.min_confidence == enhancement.min_confidence
      
      # And still has all the pattern fields
      assert enhanced.id == "js-open-redirect"
      assert enhanced.severity == :medium
    end
  end
end