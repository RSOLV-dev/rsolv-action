defmodule RsolvApi.Security.Patterns.Rails.Cve202222577Test do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Rails.Cve202222577
  alias RsolvApi.Security.Pattern

  describe "cve_2022_22577 pattern" do
    test "returns correct pattern structure" do
      pattern = Cve202222577.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "rails-cve-2022-22577"
      assert pattern.name == "CVE-2022-22577 - XSS in Action Pack"
      assert pattern.type == :xss
      assert pattern.severity == :medium
      assert pattern.languages == ["ruby"]
      assert pattern.frameworks == ["rails"]
      assert pattern.cwe_id == "CWE-79"
      assert pattern.owasp_category == "A03:2021"
      
      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects CSP header injection via params" do
      pattern = Cve202222577.pattern()
      
      vulnerable_code = [
        "response.headers[\"Content-Security-Policy\"] = \"default-src \#{params[:csp]}\"",
        "response.headers['Content-Security-Policy'] = \"script-src \#{params[:policy]}\"",
        "response.headers[\"Content-Security-Policy\"] = \"style-src 'self' \#{params[:csp_value]}\"",
        "response.headers[\"CSP\"] = \"connect-src \#{params[:connect_src]}\"",
        "response.headers[\"Content-Security-Policy\"] = \"default-src 'self'; script-src \#{params[:script_src]}\"",
        "response.headers[\"Content-Security-Policy\"] = params[:full_policy]"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects CSP policy builder injection" do
      pattern = Cve202222577.pattern()
      
      vulnerable_code = [
        "content_security_policy do |policy|\\n  policy.script_src params[:script_src]\\nend",
        "content_security_policy do |p|\\n  p.style_src params[:styles]\\n  p.connect_src 'self'\\nend",
        "Rails.configuration.content_security_policy do |policy|\\n  policy.default_src params[:default]\\nend",
        "config.content_security_policy do |policy|\\n  policy.font_src params[:fonts]\\nend"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects dynamic CSP directive construction" do
      pattern = Cve202222577.pattern()
      
      vulnerable_code = [
        "policy.script_src \"'self' \#{params[:external_scripts]}\"",
        "policy.style_src \"'self' \#{request.headers['X-Custom-Styles']}\"",
        "policy.default_src \"'self' \#{user_input}\"",
        "policy.connect_src \"'self' \#{params[:api_endpoints]}\"",
        "policy.img_src \"'self' data: \#{params[:image_sources]}\"",
        "policy.font_src \"'self' \#{params[:font_urls]}\""
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects CSP nonce injection vulnerabilities" do
      pattern = Cve202222577.pattern()
      
      vulnerable_code = [
        "policy.script_src \"'self' 'nonce-\#{params[:nonce]}'\"",
        "policy.style_src \"'self' 'nonce-\#{user_nonce}'\"",
        "response.headers[\"Content-Security-Policy\"] = \"script-src 'nonce-\#{params[:script_nonce]}'\"",
        "csp_nonce = params[:nonce]\\npolicy.script_src \"'nonce-\#{csp_nonce}'\""
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects controller-based CSP injection" do
      pattern = Cve202222577.pattern()
      
      vulnerable_code = [
        "class ApiController < ApplicationController\\n  before_action :set_csp\\n  def set_csp\\n    response.headers['Content-Security-Policy'] = params[:policy]\\n  end\\nend",
        "def api_endpoint\\n  response.headers['CSP'] = \"default-src \#{params[:sources]}\"\\n  render json: data\\nend",
        "response.headers['Content-Security-Policy'] = build_csp(params[:csp_config])"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "does not detect safe CSP configurations" do
      pattern = Cve202222577.pattern()
      
      safe_code = [
        "response.headers[\"Content-Security-Policy\"] = \"default-src 'self'\"",
        "policy.script_src 'self', 'unsafe-inline'",
        "policy.style_src 'self', 'https://fonts.googleapis.com'",
        "response.headers[\"Content-Security-Policy\"] = \"script-src 'self' 'unsafe-eval'\"",
        "content_security_policy do |policy|\\n  policy.default_src 'self'\\n  policy.script_src 'self'\\nend",
        "policy.connect_src 'self', 'https://api.example.com'",
        "# response.headers[\"Content-Security-Policy\"] = params[:policy]  # commented out",
        "csp_value = 'self'  # static value\\nresponse.headers[\"Content-Security-Policy\"] = \"default-src \#{csp_value}\"",
        "ALLOWED_SOURCES = ['self', 'https://cdn.example.com']\\npolicy.script_src(*ALLOWED_SOURCES)"
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "False positive detected for: #{code}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = Cve202222577.vulnerability_metadata()
      
      assert metadata.description
      assert metadata.attack_vectors
      assert metadata.business_impact  
      assert metadata.technical_impact
      assert metadata.likelihood
      assert metadata.cve_examples
      assert metadata.compliance_standards
      assert metadata.remediation_steps
      assert metadata.prevention_tips
      assert metadata.detection_methods
      assert metadata.safe_alternatives
    end

    test "vulnerability metadata contains CVE-2022-22577 specific information" do
      metadata = Cve202222577.vulnerability_metadata()
      
      assert String.contains?(String.downcase(metadata.description), "cve-2022-22577")
      assert String.contains?(String.downcase(metadata.attack_vectors), "csp")
      assert String.contains?(String.downcase(metadata.business_impact), "bypass")
      assert String.contains?(metadata.safe_alternatives, "static")
      assert String.contains?(String.downcase(metadata.prevention_tips), "validate")
      
      # Check for Rails-specific content
      assert String.contains?(String.downcase(metadata.description), "action pack")
      assert String.contains?(String.downcase(metadata.remediation_steps), "allowlist")
    end

    test "includes AST enhancement rules" do
      enhancement = Cve202222577.ast_enhancement()
      
      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has CSP injection specific rules" do
      enhancement = Cve202222577.ast_enhancement()
      
      assert enhancement.context_rules.csp_headers
      assert enhancement.context_rules.csp_directives
      assert enhancement.ast_rules.header_analysis
      assert enhancement.confidence_rules.adjustments.direct_params_usage
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = Cve202222577.enhanced_pattern()
      
      assert enhanced.id == "rails-cve-2022-22577"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = Cve202222577.pattern()
      
      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end

    test "applies to Ruby files" do
      assert Cve202222577.applies_to_file?("app/controllers/api_controller.rb", nil)
      assert Cve202222577.applies_to_file?("app/controllers/application_controller.rb", ["rails"])
      assert Cve202222577.applies_to_file?("config/application.rb", ["rails"])
      refute Cve202222577.applies_to_file?("test.js", nil)
      refute Cve202222577.applies_to_file?("script.py", nil)
    end

    test "applies to ruby files with Rails framework" do
      assert Cve202222577.applies_to_file?("app/controllers/api_controller.rb", ["rails"])
      refute Cve202222577.applies_to_file?("app/controllers/api_controller.rb", ["sinatra"])
      refute Cve202222577.applies_to_file?("app/controllers/api_controller.py", ["rails"])
    end

    test "detects bypass techniques from research" do
      pattern = Cve202222577.pattern()
      
      # Based on research findings - specific bypass patterns
      bypass_code = [
        # API response without CSP headers (CVE-2022-22577 core issue)
        "def api_endpoint\\n  render json: { data: data }, content_type: 'application/json'\\n  response.headers['Content-Security-Policy'] = params[:policy]\\nend",
        
        # CSP injection via query parameters
        "response.headers['Content-Security-Policy'] = \"default-src 'self'; script-src \#{params[:allowed_scripts]}\"",
        
        # Dynamic CSP based on user agent or headers
        "csp_policy = \"default-src 'self'; script-src \#{request.headers['X-Script-Sources']}\"\\nresponse.headers['Content-Security-Policy'] = csp_policy"
      ]
      
      for code <- bypass_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect bypass technique: #{code}"
      end
    end
  end
end