defmodule RsolvApi.Security.Patterns.Rails.DangerousProductionConfigTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Rails.DangerousProductionConfig
  alias RsolvApi.Security.Pattern

  describe "dangerous_production_config pattern" do
    test "returns correct pattern structure" do
      pattern = DangerousProductionConfig.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "rails-dangerous-production-config"
      assert pattern.name == "Dangerous Production Configuration"
      assert pattern.type == :debug_mode
      assert pattern.severity == :medium
      assert pattern.languages == ["ruby"]
      assert pattern.frameworks == ["rails"]
      assert pattern.cwe_id == "CWE-489"
      assert pattern.owasp_category == "A05:2021"
      
      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects consider_all_requests_local enabled" do
      pattern = DangerousProductionConfig.pattern()
      
      vulnerable_code = [
        "config.consider_all_requests_local = true",
        "Rails.application.configure { config.consider_all_requests_local = true }",
        "config.consider_all_requests_local=true",
        "  config.consider_all_requests_local = true",
        "app.config.consider_all_requests_local = true"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects caching disabled in production" do
      pattern = DangerousProductionConfig.pattern()
      
      vulnerable_code = [
        "config.action_controller.perform_caching = false",
        "config.action_controller.perform_caching=false",
        "Rails.application.configure { config.action_controller.perform_caching = false }",
        "  config.action_controller.perform_caching = false"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects debug log level in production" do
      pattern = DangerousProductionConfig.pattern()
      
      vulnerable_code = [
        "config.log_level = :debug",
        "config.log_level=:debug",
        "Rails.application.configure { config.log_level = :debug }",
        "  config.log_level = :debug",
        "config.logger.level = :debug"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects eager_load disabled" do
      pattern = DangerousProductionConfig.pattern()
      
      vulnerable_code = [
        "config.eager_load = false",
        "config.eager_load=false",
        "Rails.application.configure { config.eager_load = false }",
        "  config.eager_load = false"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects cache_classes disabled" do
      pattern = DangerousProductionConfig.pattern()
      
      vulnerable_code = [
        "config.cache_classes = false",
        "config.cache_classes=false",
        "Rails.application.configure { config.cache_classes = false }",
        "  config.cache_classes = false"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects development/debugging gems in production" do
      pattern = DangerousProductionConfig.pattern()
      
      vulnerable_code = [
        "gem 'byebug'",
        "gem \"byebug\"",
        "gem 'pry'",
        "gem \"pry\"",
        "gem 'pry-rails'",
        "gem \"pry-rails\"",
        "  gem 'byebug'",
        "gem 'byebug', '~> 11.0'"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects asset debugging enabled" do
      pattern = DangerousProductionConfig.pattern()
      
      vulnerable_code = [
        "config.assets.debug = true",
        "config.assets.debug=true",
        "Rails.application.configure { config.assets.debug = true }",
        "  config.assets.debug = true"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects asset compression disabled" do
      pattern = DangerousProductionConfig.pattern()
      
      vulnerable_code = [
        "config.assets.compress = false",
        "config.assets.compress=false",
        "Rails.application.configure { config.assets.compress = false }",
        "  config.assets.compress = false"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects development mode enablement" do
      pattern = DangerousProductionConfig.pattern()
      
      vulnerable_code = [
        "Rails.env = 'development'",
        "ENV['RAILS_ENV'] = 'development'",
        "config.force_ssl = false",
        "config.ssl_options = { secure_cookies: false }"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects error display configuration issues" do
      pattern = DangerousProductionConfig.pattern()
      
      vulnerable_code = [
        "config.action_dispatch.show_exceptions = true",
        "config.action_dispatch.show_exceptions=true",
        "config.action_dispatch.show_detailed_exceptions = true"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "does not detect safe production configurations" do
      pattern = DangerousProductionConfig.pattern()
      
      safe_code = [
        "config.consider_all_requests_local = false",
        "config.consider_all_requests_local = Rails.env.development?",
        "config.action_controller.perform_caching = true",
        "config.log_level = :info",
        "config.log_level = :warn",
        "config.eager_load = true",
        "config.cache_classes = true",
        "config.assets.debug = false",
        "config.assets.compress = true",
        "# gem 'byebug' - commented out",
        "config.force_ssl = true",
        "Rails.env = 'production'",
        "ENV['RAILS_ENV'] = 'production'",
        "config.action_dispatch.show_exceptions = false"
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "False positive detected for: #{code}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = DangerousProductionConfig.vulnerability_metadata()
      
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

    test "vulnerability metadata contains production configuration specific information" do
      metadata = DangerousProductionConfig.vulnerability_metadata()
      
      assert String.contains?(String.downcase(metadata.description), "production")
      assert String.contains?(String.downcase(metadata.attack_vectors), "debug")
      assert String.contains?(metadata.business_impact, "information disclosure")
      assert String.contains?(metadata.safe_alternatives, "production")
      assert String.contains?(String.downcase(metadata.prevention_tips), "environment")
      
      # Check for configuration-specific content
      assert String.contains?(String.downcase(metadata.description), "development setting")
      assert String.contains?(String.downcase(metadata.remediation_steps), "consider_all_requests_local")
    end

    test "includes AST enhancement rules" do
      enhancement = DangerousProductionConfig.ast_enhancement()
      
      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has production configuration specific rules" do
      enhancement = DangerousProductionConfig.ast_enhancement()
      
      assert enhancement.context_rules.config_methods
      assert enhancement.context_rules.dangerous_development_settings
      assert enhancement.ast_rules.configuration_analysis
      assert enhancement.confidence_rules.adjustments.development_setting_in_production
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = DangerousProductionConfig.enhanced_pattern()
      
      assert enhanced.id == "rails-dangerous-production-config"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = DangerousProductionConfig.pattern()
      
      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end

    test "applies to Ruby files" do
      assert DangerousProductionConfig.applies_to_file?("config/environments/production.rb")
      assert DangerousProductionConfig.applies_to_file?("config/application.rb", ["rails"])
      assert DangerousProductionConfig.applies_to_file?("Gemfile", ["rails"])
      refute DangerousProductionConfig.applies_to_file?("test.js")
      refute DangerousProductionConfig.applies_to_file?("script.py")
    end

    test "applies to ruby files with Rails framework" do
      assert DangerousProductionConfig.applies_to_file?("config/environments/production.rb", ["rails"])
      refute DangerousProductionConfig.applies_to_file?("config/environments/production.rb", ["sinatra"])
      refute DangerousProductionConfig.applies_to_file?("config/application.py", ["rails"])
    end
  end
end