defmodule RsolvApi.Security.Patterns.Rails.DynamicFinderInjectionTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Rails.DynamicFinderInjection
  alias RsolvApi.Security.Pattern

  describe "dynamic_finder_injection pattern" do
    test "returns correct pattern structure" do
      pattern = DynamicFinderInjection.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "rails-dynamic-finder-injection"
      assert pattern.name == "Dynamic Finder Injection"
      assert pattern.type == :sql_injection
      assert pattern.severity == :high
      assert pattern.languages == ["ruby"]
      assert pattern.frameworks == ["rails"]
      assert pattern.default_tier == :ai
      assert pattern.cwe_id == "CWE-89"
      assert pattern.owasp_category == "A03:2021"
      
      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects send with dynamic find_by methods" do
      pattern = DynamicFinderInjection.pattern()
      
      vulnerable_code = [
        "User.send(\"find_by_\#{params[:field]}\", params[:value])",
        "Post.send(\"find_by_\#{user_input}\", value)",
        "Article.send(\"find_by_\#{request[:column]}\", data)",
        "@model.send(\"find_by_\#{params[:attr]}\", params[:val])"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects method calls with dynamic finders" do
      pattern = DynamicFinderInjection.pattern()
      
      vulnerable_code = [
        "User.method(\"find_by_\#{params[:field]}\").call(value)",
        "Post.method(\"find_by_\#{column_name}\").call(params[:value])",
        "model.method(\"find_by_\#{user_field}\").call(data)"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects send with interpolated method names" do
      pattern = DynamicFinderInjection.pattern()
      
      vulnerable_code = [
        "User.send(\"\#{params[:method]}_users\")",
        "Post.send(\"\#{action}_posts\", data)",
        "model.send(\"\#{params[:action]}\")",
        "User.send(\"\#{params[:method]}=\", value)",
        "@object.send(\"\#{user_method}=\", params[:value])"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects send with params directly" do
      pattern = DynamicFinderInjection.pattern()
      
      vulnerable_code = [
        "User.send(params[:method], value)",
        "Post.send(request.params[:action])",
        "@model.send(user_params[:method], data)",
        "object.send(params[:attribute])"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects CVE-2012-6496 vulnerability pattern" do
      pattern = DynamicFinderInjection.pattern()
      
      # This CVE involved dynamic finders with unexpected data types
      vulnerable_code = [
        "User.send(\"find_by_\#{params[:field]}\", params[:value])",
        "Model.send(\"find_all_by_\#{column}\", user_input)"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect CVE-2012-6496 pattern: #{code}"
      end
    end

    test "does not detect safe method calls" do
      pattern = DynamicFinderInjection.pattern()
      
      safe_code = [
        "User.find_by(name: params[:name])",
        "Post.where(title: params[:title])",
        "User.send(:save)",
        "model.send(:valid?)",
        "User.find_by_name(params[:name])",  # Static find_by_name is safe
        "Post.find_by_id(params[:id])",      # Static find_by_id is safe
        "allowed_methods = [:find_by_name, :find_by_email]\nif allowed_methods.include?(method.to_sym)\n  User.send(method, value)\nend"
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "False positive detected for: #{code}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = DynamicFinderInjection.vulnerability_metadata()
      
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

    test "vulnerability metadata contains metaprogramming specific information" do
      metadata = DynamicFinderInjection.vulnerability_metadata()
      
      assert String.contains?(String.downcase(metadata.description), "metaprogramming")
      assert String.contains?(String.downcase(metadata.attack_vectors), "send")
      assert String.contains?(metadata.business_impact, "database")
      assert String.contains?(metadata.safe_alternatives, "whitelist")
      assert String.contains?(metadata.prevention_tips, "dynamic")
    end

    test "includes AST enhancement rules" do
      enhancement = DynamicFinderInjection.ast_enhancement()
      
      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has metaprogramming specific rules" do
      enhancement = DynamicFinderInjection.ast_enhancement()
      
      assert enhancement.context_rules.metaprogramming_methods
      assert enhancement.context_rules.dangerous_patterns
      assert enhancement.ast_rules.method_analysis
      assert enhancement.confidence_rules.adjustments.uses_whitelist
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = DynamicFinderInjection.enhanced_pattern()
      
      assert enhanced.id == "rails-dynamic-finder-injection"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = DynamicFinderInjection.pattern()
      
      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end

    test "applies to Ruby files" do
      assert DynamicFinderInjection.applies_to_file?("app/models/user.rb")
      assert DynamicFinderInjection.applies_to_file?("app/controllers/posts_controller.rb")
      assert DynamicFinderInjection.applies_to_file?("lib/search_service.rb", ["rails"])
      refute DynamicFinderInjection.applies_to_file?("test.js")
      refute DynamicFinderInjection.applies_to_file?("script.py")
    end

    test "applies to ruby files with Rails framework" do
      assert DynamicFinderInjection.applies_to_file?("service.rb", ["rails"])
      refute DynamicFinderInjection.applies_to_file?("service.rb", ["sinatra"])
      refute DynamicFinderInjection.applies_to_file?("service.py", ["rails"])
    end
  end
end