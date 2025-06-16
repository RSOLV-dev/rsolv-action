defmodule RsolvApi.Security.Patterns.Rails.InsecureCorsTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Rails.InsecureCors
  alias RsolvApi.Security.Pattern

  describe "insecure_cors pattern" do
    test "returns correct pattern structure" do
      pattern = InsecureCors.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "rails-insecure-cors"
      assert pattern.name == "Insecure CORS Configuration"
      assert pattern.type == :security_misconfiguration
      assert pattern.severity == :medium
      assert pattern.languages == ["ruby"]
      assert pattern.frameworks == ["rails"]
      assert pattern.default_tier == :public
      assert pattern.cwe_id == "CWE-346"
      assert pattern.owasp_category == "A05:2021"
      
      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects wildcard origins with credentials" do
      pattern = InsecureCors.pattern()
      
      vulnerable_code = [
        "origins \"*\"",
        "origins '*'",
        "resource '*', origins: '*', credentials: true",
        "resource '/*', origins: '*', credentials: true",
        "resource '/api/*', origins: '*', credentials: true",
        "allow do\n  origins '*'\n  credentials true\nend"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects wildcard headers configuration" do
      pattern = InsecureCors.pattern()
      
      vulnerable_code = [
        "headers :any",
        "headers '*'",
        "headers \"*\"",
        "resource '*', headers: :any",
        "resource '*', headers: '*'",
        "allow do\n  headers :any\nend",
        "allow do\n  headers '*'\nend"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects wildcard methods configuration" do
      pattern = InsecureCors.pattern()
      
      vulnerable_code = [
        "methods :any",
        "methods '*'",
        "methods \"*\"",
        "resource '*', methods: :any",
        "resource '*', methods: '*'",
        "allow do\n  methods :any\nend",
        "allow do\n  methods '*'\nend"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects dangerous wildcard origins with credentials multiline" do
      pattern = InsecureCors.pattern()
      
      vulnerable_code = [
        "origins \"*\"\ncredentials true",
        "origins '*'\ncredentials true", 
        "resource '*' do\n  origins '*'\n  credentials true\nend",
        "allow do\n  origins '*'\n  credentials true\nend",
        "config.middleware.insert_before 0, Rack::Cors do\n  allow do\n    origins '*'\n    credentials true\n  end\nend"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects insecure rack-cors configurations" do
      pattern = InsecureCors.pattern()
      
      vulnerable_code = [
        "Rack::Cors do\n  allow do\n    origins '*'\n    resource '*'\n  end\nend",
        "use Rack::Cors do\n  allow do\n    origins '*'\n  end\nend",
        "config.middleware.use Rack::Cors do\n  allow do\n    origins '*'\n    credentials true\n  end\nend"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects insecure response header configurations" do
      pattern = InsecureCors.pattern()
      
      vulnerable_code = [
        "response.headers['Access-Control-Allow-Origin'] = '*'",
        "response.headers[\"Access-Control-Allow-Origin\"] = \"*\"",
        "headers['Access-Control-Allow-Origin'] = '*'",
        "headers[\"Access-Control-Allow-Origin\"] = \"*\""
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects insecure regex and dynamic origins" do
      pattern = InsecureCors.pattern()
      
      vulnerable_code = [
        "origins /.*\\.domain\\.com/",
        "origins /https?:\\/\\/.*/",
        "origins ->(source, env) { true }",
        "origins lambda { |source, env| true }",
        "origins proc { |source, env| true }"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "does not detect secure CORS configurations" do
      pattern = InsecureCors.pattern()
      
      safe_code = [
        "origins \"https://example.com\"",
        "origins ['https://example.com', 'https://api.example.com']",
        "origins \"https://example.com\"\ncredentials true",
        "resource '*', origins: 'https://example.com', credentials: true",
        "headers ['Content-Type', 'Authorization']",
        "methods ['GET', 'POST', 'PUT', 'DELETE']",
        "origins \"https://example.com\"\nheaders ['Content-Type']\nmethods ['GET', 'POST']",
        "# origins '*'  - commented out unsafe config",
        "allow do\n  origins 'https://example.com'\n  credentials true\nend"
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "False positive detected for: #{code}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = InsecureCors.vulnerability_metadata()
      
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

    test "vulnerability metadata contains CORS specific information" do
      metadata = InsecureCors.vulnerability_metadata()
      
      assert String.contains?(String.downcase(metadata.description), "cors")
      assert String.contains?(String.downcase(metadata.attack_vectors), "origin")
      assert String.contains?(String.downcase(metadata.business_impact), "unauthorized access")
      assert String.contains?(metadata.safe_alternatives, "https://")
      assert String.contains?(String.downcase(metadata.prevention_tips), "wildcard")
      
      # Check for CORS-specific content
      assert String.contains?(String.downcase(metadata.description), "cross-origin")
      assert String.contains?(String.downcase(metadata.remediation_steps), "rack::cors")
    end

    test "includes AST enhancement rules" do
      enhancement = InsecureCors.ast_enhancement()
      
      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has CORS specific rules" do
      enhancement = InsecureCors.ast_enhancement()
      
      assert enhancement.context_rules.cors_methods
      assert enhancement.context_rules.dangerous_origins
      assert enhancement.ast_rules.cors_analysis
      assert enhancement.confidence_rules.adjustments.wildcard_origin
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = InsecureCors.enhanced_pattern()
      
      assert enhanced.id == "rails-insecure-cors"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = InsecureCors.pattern()
      
      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end

    test "applies to Ruby files" do
      assert InsecureCors.applies_to_file?("config/initializers/cors.rb")
      assert InsecureCors.applies_to_file?("config/application.rb", ["rails"])
      assert InsecureCors.applies_to_file?("app/controllers/application_controller.rb", ["rails"])
      refute InsecureCors.applies_to_file?("test.js")
      refute InsecureCors.applies_to_file?("script.py")
    end

    test "applies to ruby files with Rails framework" do
      assert InsecureCors.applies_to_file?("config/initializers/cors.rb", ["rails"])
      refute InsecureCors.applies_to_file?("config/initializers/cors.rb", ["sinatra"])
      refute InsecureCors.applies_to_file?("config/cors.py", ["rails"])
    end
  end
end