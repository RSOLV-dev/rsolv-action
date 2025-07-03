defmodule Rsolv.Security.Patterns.Javascript.SsrfTest do
  use ExUnit.Case, async: true
  doctest Rsolv.Security.Patterns.Javascript.Ssrf
  
  alias Rsolv.Security.Pattern
  alias Rsolv.Security.Patterns.Javascript.Ssrf

  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = Ssrf.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-ssrf"
      assert pattern.name == "Server-Side Request Forgery (SSRF)"
      assert pattern.type == :ssrf
      assert pattern.severity == :high
      assert pattern.languages == ["javascript", "typescript"]
      assert pattern.cwe_id == "CWE-918"
      assert pattern.owasp_category == "A10:2021"
    end

    test "pattern has required metadata" do
      pattern = Ssrf.pattern()
      
      assert pattern.description =~ "Server-side"
      assert pattern.recommendation =~ "allowlist"
      assert is_map(pattern.test_cases)
      assert is_list(pattern.test_cases.vulnerable)
      assert is_list(pattern.test_cases.safe)
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive vulnerability metadata" do
      metadata = Ssrf.vulnerability_metadata()
      
      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert is_list(metadata.references)
      assert is_list(metadata.attack_vectors)
      assert is_list(metadata.real_world_impact)
      assert is_list(metadata.cve_examples)
      assert is_list(metadata.safe_alternatives)
    end

    test "metadata includes required reference types" do
      metadata = Ssrf.vulnerability_metadata()
      references = metadata.references
      
      assert Enum.any?(references, &(&1.type == :cwe))
      assert Enum.any?(references, &(&1.type == :owasp))
    end
  end

  describe "detection tests" do
    test "detects axios requests with user input" do
      pattern = Ssrf.pattern()
      
      vulnerable_codes = [
        ~S|axios.get(req.body.url)|,
        ~S|axios.post(userProvidedUrl, data)|,
        ~S|axios.put(params.webhook_url)|
      ]
      
      for code <- vulnerable_codes do
        assert Regex.match?(pattern.regex, code), "Should detect: #{code}"
      end
    end

    test "detects fetch with user input" do
      pattern = Ssrf.pattern()
      
      vulnerable_codes = [
        ~S|fetch(userInput)|,
        ~S|fetch(req.query.url)|,
        ~S|fetch(data.callback_url).then(res => res.json())|
      ]
      
      for code <- vulnerable_codes do
        assert Regex.match?(pattern.regex, code), "Should detect: #{code}"
      end
    end

    test "detects request library with user input" do
      pattern = Ssrf.pattern()
      
      vulnerable_codes = [
        ~S|request(params.webhook_url, (err, res) => {})|,
        ~S|request.get(userUrl, callback)|,
        ~S|request.post({url: input.endpoint})|
      ]
      
      for code <- vulnerable_codes do
        assert Regex.match?(pattern.regex, code), "Should detect: #{code}"
      end
    end

    test "detects http/https module with user input" do
      pattern = Ssrf.pattern()
      
      vulnerable_codes = [
        ~S|http.get(req.body.url, (res) => {})|,
        ~S|https.request(userProvidedUrl, options)|,
        ~S|http.request(data.webhook, callback)|
      ]
      
      for code <- vulnerable_codes do
        assert Regex.match?(pattern.regex, code), "Should detect: #{code}"
      end
    end

    test "detects various input sources" do
      pattern = Ssrf.pattern()
      
      vulnerable_codes = [
        ~S|axios.get(req.params.api)|,
        ~S|fetch(request.body.callback)|,
        ~S|http.get(user.webhookUrl)|,
        ~S|axios.post(inputData.endpoint)|
      ]
      
      for code <- vulnerable_codes do
        assert Regex.match?(pattern.regex, code), "Should detect: #{code}"
      end
    end
  end

  describe "safe code validation" do
    test "does not match hardcoded URLs" do
      pattern = Ssrf.pattern()
      
      safe_codes = [
        ~S|axios.get("https://api.example.com/data")|,
        ~S|fetch("http://localhost:3000/api")|,
        ~S|request.post("https://webhook.site/static")|,
        ~S|http.get("https://api.internal.com/status")|
      ]
      
      for code <- safe_codes do
        refute Regex.match?(pattern.regex, code), "Should not match: #{code}"
      end
    end

    test "does not match allowlisted URLs" do
      pattern = Ssrf.pattern()
      
      # These patterns genuinely don't have user input going directly to the URL
      safe_codes = [
        ~S|axios.get(ALLOWED_APIS[req.body.api_name])|,
        ~S|const endpoint = getEndpointFromConfig(req.body.service); axios.get(endpoint)|
      ]
      
      for code <- safe_codes do
        refute Regex.match?(pattern.regex, code), "Should not match: #{code}"
      end
    end

    test "does not match validated input" do
      pattern = Ssrf.pattern()
      
      safe_code = """
      const url = validateAndSanitizeUrl(userInput);
      if (url) {
        axios.get(url);
      }
      """
      
      refute Regex.match?(pattern.regex, safe_code)
    end
  end

  describe "applies_to_file?/1" do
    test "applies to JavaScript files" do
      assert Ssrf.applies_to_file?("webhook-handler.js", nil)
      assert Ssrf.applies_to_file?("api-client.mjs", nil)
      assert Ssrf.applies_to_file?("src/services/http.js", nil)
    end

    test "applies to TypeScript files" do
      assert Ssrf.applies_to_file?("api-service.ts", nil)
      assert Ssrf.applies_to_file?("webhook.tsx", nil)
      assert Ssrf.applies_to_file?("lib/fetcher.ts", nil)
    end

    test "does not apply to non-JS/TS files" do
      refute Ssrf.applies_to_file?("api.py", nil)
      refute Ssrf.applies_to_file?("webhook.rb", nil)
      refute Ssrf.applies_to_file?("README.md", nil)
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns complete AST enhancement structure" do
      enhancement = Ssrf.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
    end
    
    test "AST rules specify HTTP client patterns" do
      enhancement = Ssrf.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert is_list(enhancement.ast_rules.callee_patterns)
      assert is_map(enhancement.ast_rules.argument_analysis)
      assert enhancement.ast_rules.argument_analysis.has_url_parameter == true
    end
    
    test "context rules include URL validation checks" do
      enhancement = Ssrf.ast_enhancement()
      
      assert is_list(enhancement.context_rules.exclude_paths)
      assert enhancement.context_rules.exclude_if_url_validated == true
      assert enhancement.context_rules.exclude_if_allowlisted == true
      assert is_list(enhancement.context_rules.safe_url_patterns)
    end
    
    test "confidence rules provide appropriate scoring" do
      enhancement = Ssrf.ast_enhancement()
      
      assert is_number(enhancement.confidence_rules.base)
      assert is_map(enhancement.confidence_rules.adjustments)
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "direct_user_url")
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "url_validation_present")
      assert enhancement.min_confidence == 0.7
    end
  end
end