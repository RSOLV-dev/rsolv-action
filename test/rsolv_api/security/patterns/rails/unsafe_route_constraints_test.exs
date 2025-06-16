defmodule RsolvApi.Security.Patterns.Rails.UnsafeRouteConstraintsTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Rails.UnsafeRouteConstraints
  alias RsolvApi.Security.Pattern

  describe "unsafe_route_constraints pattern" do
    test "returns correct pattern structure" do
      pattern = UnsafeRouteConstraints.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "rails-unsafe-route-constraints"
      assert pattern.name == "Unsafe Route Constraints"
      assert pattern.type == :broken_access_control
      assert pattern.severity == :high
      assert pattern.languages == ["ruby"]
      assert pattern.frameworks == ["rails"]
      assert pattern.default_tier == :protected
      assert pattern.cwe_id == "CWE-285"
      assert pattern.owasp_category == "A01:2021"
      
      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects overly permissive regex constraints" do
      pattern = UnsafeRouteConstraints.pattern()
      
      vulnerable_code = [
        "constraints: { id: /.*/ }",
        "constraints: { slug: /.*/ }",
        "get \"users/:id\", constraints: { id: /.*/ }",
        "constraints id: /.*/",
        "constraints({ id: /.*/ })",
        "constraints: { param: /.*/ }, to: 'controller#action'"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects constraints with parameter interpolation" do
      pattern = UnsafeRouteConstraints.pattern()
      
      vulnerable_code = [
        "constraints: { id: /\#{params[:pattern]}/ }",
        "constraints: { slug: /\#{user_input}/ }",
        "constraints: { param: /\#{request.params[:regex]}/ }",
        "constraints id: /\#{params[:id_pattern]}/",
        "constraints({ slug: /\#{params[:constraint]}/ })"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects lambda constraints with eval" do
      pattern = UnsafeRouteConstraints.pattern()
      
      vulnerable_code = [
        "constraints: lambda { |req| eval(req.params[:code]) }",
        "constraints lambda { |request| eval(params[:check]) }",
        "constraints: -> { eval(user_input) }",
        "constraints: proc { eval(request.params[:constraint]) }",
        "constraints: lambda { |req| instance_eval(req.params[:code]) }"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects lambda constraints that always return true" do
      pattern = UnsafeRouteConstraints.pattern()
      
      vulnerable_code = [
        "constraints lambda { |req| true }",
        "constraints: -> { true }",
        "constraints proc { |request| true }",
        "constraints: lambda { |r| true }",
        "constraints lambda { true }"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects unsafe subdomain constraints" do
      pattern = UnsafeRouteConstraints.pattern()
      
      vulnerable_code = [
        "constraints subdomain: /.*/",
        "constraints: { subdomain: /.*/ }",
        ~S"constraints subdomain: /#{params[:sub]}/",
        ~S"constraints: { subdomain: /#{user_input}/ }",
        "constraints subdomain: /.*/, to: 'admin#index'"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects constraints with send method calls" do
      pattern = UnsafeRouteConstraints.pattern()
      
      vulnerable_code = [
        "constraints: lambda { |req| req.send(params[:method]) }",
        "constraints lambda { |r| r.send(user_input) }",
        "constraints: -> { object.send(params[:action]) }",
        "constraints proc { self.send(request.params[:call]) }"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects constraints with method_missing calls" do
      pattern = UnsafeRouteConstraints.pattern()
      
      vulnerable_code = [
        "constraints: lambda { |req| method_missing(params[:method]) }",
        "constraints lambda { method_missing(user_input, args) }",
        "constraints: -> { method_missing(request.params[:missing]) }"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects constraints with system calls" do
      pattern = UnsafeRouteConstraints.pattern()
      
      vulnerable_code = [
        "constraints: lambda { |req| system(params[:cmd]) }",
        "constraints lambda { system(user_input) }",
        ~S"constraints: -> { `#{params[:command]}` }",
        "constraints proc { exec(request.params[:exec]) }"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects unsafe format constraints" do
      pattern = UnsafeRouteConstraints.pattern()
      
      vulnerable_code = [
        "constraints: { format: /.*/ }",
        "constraints format: /.*/",
        ~S"constraints: { format: /#{params[:format]}/ }",
        "get 'posts/:id', constraints: { format: /.*/ }"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects unsafe host constraints" do
      pattern = UnsafeRouteConstraints.pattern()
      
      vulnerable_code = [
        "constraints: { host: /.*/ }",
        "constraints host: /.*/",
        ~S"constraints: { host: /#{params[:hostname]}/ }",
        "constraints({ host: /.*\\.example\\.com/ })"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "does not detect safe constraint usage" do
      pattern = UnsafeRouteConstraints.pattern()
      
      safe_code = [
        "constraints: { id: /\\d+/ }",  # Specific numeric pattern
        "constraints: { slug: /[a-z0-9-]+/ }",  # Alphanumeric with dashes
        "constraints subdomain: 'admin'",  # Static string
        "constraints: { format: /json|xml/ }",  # Specific formats
        "constraints lambda { |req| req.subdomain == 'api' }",  # Safe comparison
        "constraints: -> { Rails.env.production? }",  # Environment check
        "constraints: { id: /\\A\\d+\\z/ }",  # Anchored numeric pattern
        "# constraints: { id: /.*/ } - commented out",  # Commented code
        "constraints: { host: 'example.com' }",  # Static host
        "constraints proc { |req| ALLOWED_HOSTS.include?(req.host) }"  # Whitelist check
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "False positive detected for: #{code}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = UnsafeRouteConstraints.vulnerability_metadata()
      
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

    test "vulnerability metadata contains route constraint specific information" do
      metadata = UnsafeRouteConstraints.vulnerability_metadata()
      
      assert String.contains?(String.downcase(metadata.description), "route constraint")
      assert String.contains?(String.downcase(metadata.attack_vectors), "regex")
      assert String.contains?(metadata.business_impact, "access control bypass")
      assert String.contains?(metadata.safe_alternatives, "whitelist")
      assert String.contains?(String.downcase(metadata.prevention_tips), "constraint")
      
      # Check for security concepts found in research
      assert String.contains?(String.downcase(metadata.description), "broken access control")
      assert String.contains?(String.downcase(metadata.remediation_steps), "lambda")
    end

    test "includes AST enhancement rules" do
      enhancement = UnsafeRouteConstraints.ast_enhancement()
      
      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has route constraint specific rules" do
      enhancement = UnsafeRouteConstraints.ast_enhancement()
      
      assert enhancement.context_rules.dangerous_patterns
      assert enhancement.context_rules.constraint_methods
      assert enhancement.ast_rules.route_analysis
      assert enhancement.confidence_rules.adjustments.overly_permissive_regex
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = UnsafeRouteConstraints.enhanced_pattern()
      
      assert enhanced.id == "rails-unsafe-route-constraints"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = UnsafeRouteConstraints.pattern()
      
      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end

    test "applies to Ruby files" do
      assert UnsafeRouteConstraints.applies_to_file?("config/routes.rb")
      assert UnsafeRouteConstraints.applies_to_file?("app/controllers/application_controller.rb", ["rails"])
      assert UnsafeRouteConstraints.applies_to_file?("config/application.rb", ["rails"])
      refute UnsafeRouteConstraints.applies_to_file?("test.js")
      refute UnsafeRouteConstraints.applies_to_file?("script.py")
    end

    test "applies to ruby files with Rails framework" do
      assert UnsafeRouteConstraints.applies_to_file?("routes.rb", ["rails"])
      refute UnsafeRouteConstraints.applies_to_file?("routes.rb", ["sinatra"])
      refute UnsafeRouteConstraints.applies_to_file?("routes.py", ["rails"])
    end
  end
end