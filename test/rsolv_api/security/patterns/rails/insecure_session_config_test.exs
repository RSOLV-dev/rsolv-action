defmodule RsolvApi.Security.Patterns.Rails.InsecureSessionConfigTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Rails.InsecureSessionConfig
  alias RsolvApi.Security.Pattern

  describe "insecure_session_config pattern" do
    test "returns correct pattern structure" do
      pattern = InsecureSessionConfig.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "rails-insecure-session-config"
      assert pattern.name == "Insecure Session Configuration"
      assert pattern.type == :security_misconfiguration
      assert pattern.severity == :medium
      assert pattern.languages == ["ruby"]
      assert pattern.frameworks == ["rails"]
      assert pattern.cwe_id == "CWE-614"
      assert pattern.owasp_category == "A05:2021"
      
      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects session store without secure flag" do
      pattern = InsecureSessionConfig.pattern()
      
      vulnerable_code = [
        "config.session_store :cookie_store, key: '_app_session'",
        "Rails.application.config.session_store :cookie_store, key: '_app_session'",
        "config.session_store :cookie_store, key: '_myapp_session', httponly: true",
        "Rails.application.config.session_store :cookie_store, key: 'session_id'",
        "config.session_store :active_record_store, key: '_session'",
        "config.session_store :memory_store, key: 'app_session'"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects session configuration with explicit secure: false" do
      pattern = InsecureSessionConfig.pattern()
      
      vulnerable_code = [
        "config.session_store :cookie_store, key: '_app_session', secure: false",
        "Rails.application.config.session_store :cookie_store, secure: false",
        "config.session_store :cookie_store, key: '_session', secure: false, httponly: true",
        "config.session_store :active_record_store, secure: false"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects session configuration with explicit httponly: false" do
      pattern = InsecureSessionConfig.pattern()
      
      vulnerable_code = [
        "config.session_store :cookie_store, key: '_app_session', httponly: false",
        "Rails.application.config.session_store :cookie_store, httponly: false",
        "config.session_store :cookie_store, key: '_session', httponly: false, secure: true",
        "config.session_store :active_record_store, httponly: false"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects session configuration with same_site: :none" do
      pattern = InsecureSessionConfig.pattern()
      
      vulnerable_code = [
        "config.session_store :cookie_store, same_site: :none",
        "Rails.application.config.session_store :cookie_store, same_site: :none",
        "config.session_store :cookie_store, key: '_session', same_site: :none",
        "config.session_store :active_record_store, same_site: :none, secure: true"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects weak session secrets" do
      pattern = InsecureSessionConfig.pattern()
      
      vulnerable_code = [
        ~S|config.session_store :cookie_store, secret: "12345"|,
        ~S|Rails.application.config.session_store :cookie_store, secret: 'weak'|,
        ~S|config.session_store :cookie_store, secret: "password"|,
        ~S|config.session_store :cookie_store, secret: "abc123"|,
        ~S|config.session_store :cookie_store, secret: 'test123'|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects basic session store configurations without security flags" do
      pattern = InsecureSessionConfig.pattern()
      
      vulnerable_code = [
        "config.session_store :cookie_store",
        "Rails.application.config.session_store :cookie_store",
        "config.session_store :active_record_store",
        "config.session_store :memory_store"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects session configuration with disabled format constraints" do
      pattern = InsecureSessionConfig.pattern()
      
      vulnerable_code = [
        "config.session_store :cookie_store, format: false",
        "Rails.application.config.session_store :cookie_store, format: nil",
        "config.session_store :cookie_store, key: '_session', format: false"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects multiline session configurations" do
      pattern = InsecureSessionConfig.pattern()
      
      vulnerable_code = [
        "Rails.application.config.session_store :cookie_store,\n  key: '_app_session'",
        "config.session_store :cookie_store,\n  key: '_session',\n  httponly: false",
        "Rails.application.config.session_store :cookie_store,\n  secure: false,\n  httponly: true"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "does not detect secure session configurations" do
      pattern = InsecureSessionConfig.pattern()
      
      safe_code = [
        "config.session_store :cookie_store, key: '_app_session', secure: true, httponly: true, same_site: :strict",
        "Rails.application.config.session_store :cookie_store, secure: true, httponly: true",
        "config.session_store :cookie_store, key: '_session', secure: true, httponly: true, same_site: :lax",
        ~S|config.session_store :cookie_store, secret: Rails.application.secrets.secret_key_base|,
        ~S|config.session_store :cookie_store, secret: ENV['SECRET_TOKEN']|,
        "# config.session_store :cookie_store, key: '_app_session' - commented out",
        "Rails.application.config.session_store :cookie_store, secure: Rails.env.production?, httponly: true"
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "False positive detected for: #{code}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = InsecureSessionConfig.vulnerability_metadata()
      
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

    test "vulnerability metadata contains session security specific information" do
      metadata = InsecureSessionConfig.vulnerability_metadata()
      
      assert String.contains?(String.downcase(metadata.description), "session")
      assert String.contains?(String.downcase(metadata.attack_vectors), "cookie")
      assert String.contains?(metadata.business_impact, "session hijacking")
      assert String.contains?(metadata.safe_alternatives, "secure: true")
      assert String.contains?(String.downcase(metadata.prevention_tips), "httponly")
      
      # Check for CVE references found in research
      assert String.contains?(metadata.cve_examples, "CVE-2024-26144")
      assert String.contains?(String.downcase(metadata.description), "session cookie")
    end

    test "includes AST enhancement rules" do
      enhancement = InsecureSessionConfig.ast_enhancement()
      
      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has session configuration specific rules" do
      enhancement = InsecureSessionConfig.ast_enhancement()
      
      assert enhancement.context_rules.session_config_methods
      assert enhancement.context_rules.security_flags
      assert enhancement.ast_rules.config_analysis
      assert enhancement.confidence_rules.adjustments.missing_security_flags
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = InsecureSessionConfig.enhanced_pattern()
      
      assert enhanced.id == "rails-insecure-session-config"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = InsecureSessionConfig.pattern()
      
      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end

    test "applies to Ruby files" do
      assert InsecureSessionConfig.applies_to_file?("config/application.rb")
      assert InsecureSessionConfig.applies_to_file?("config/environments/production.rb", ["rails"])
      assert InsecureSessionConfig.applies_to_file?("config/initializers/session_store.rb", ["rails"])
      refute InsecureSessionConfig.applies_to_file?("test.js")
      refute InsecureSessionConfig.applies_to_file?("script.py")
    end

    test "applies to ruby files with Rails framework" do
      assert InsecureSessionConfig.applies_to_file?("config/application.rb", ["rails"])
      refute InsecureSessionConfig.applies_to_file?("config/application.rb", ["sinatra"])
      refute InsecureSessionConfig.applies_to_file?("config/application.py", ["rails"])
    end
  end
end