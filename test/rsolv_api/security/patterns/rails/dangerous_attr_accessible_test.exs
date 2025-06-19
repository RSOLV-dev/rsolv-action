defmodule RsolvApi.Security.Patterns.Rails.DangerousAttrAccessibleTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Rails.DangerousAttrAccessible
  alias RsolvApi.Security.Pattern

  describe "dangerous_attr_accessible pattern" do
    test "returns correct pattern structure" do
      pattern = DangerousAttrAccessible.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "rails-dangerous-attr-accessible"
      assert pattern.name == "Dangerous attr_accessible Usage"
      assert pattern.type == :mass_assignment
      assert pattern.severity == :high
      assert pattern.languages == ["ruby"]
      assert pattern.frameworks == ["rails"]
      assert pattern.default_tier == :ai
      assert pattern.cwe_id == "CWE-915"
      assert pattern.owasp_category == "A01:2021"
      
      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects dangerous attr_accessible with admin/role fields" do
      pattern = DangerousAttrAccessible.pattern()
      
      vulnerable_code = [
        "attr_accessible :name, :email, :admin",
        "attr_accessible :role, :username",
        "attr_accessible :is_admin, :profile",
        "attr_accessible :user_role, :data",
        "attr_accessible :administrator, :content",
        "attr_accessible :name, :email, :role",
        "attr_accessible :permissions, :title"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects dangerous attr_accessible with as: :admin option" do
      pattern = DangerousAttrAccessible.pattern()
      
      vulnerable_code = [
        "attr_accessible :name, :email, as: :admin",
        "attr_accessible :profile, :as => :admin",
        "attr_accessible :data, as: :administrator",
        "attr_accessible :settings, :as => :superuser"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects missing attr_accessible in ActiveRecord models" do
      pattern = DangerousAttrAccessible.pattern()
      
      vulnerable_code = """
      class User < ActiveRecord::Base
        has_many :posts
        validates :email, presence: true
      end
      """
      
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
             "Failed to detect model without attr_accessible"
    end

    test "detects overly permissive attr_accessible patterns" do
      pattern = DangerousAttrAccessible.pattern()
      
      vulnerable_code = [
        "attr_accessible :password_digest",
        "attr_accessible :encrypted_password",
        "attr_accessible :api_key",
        "attr_accessible :authentication_token",
        "attr_accessible :session_token"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "does not detect safe attr_accessible usage" do
      pattern = DangerousAttrAccessible.pattern()
      
      safe_code = [
        "attr_accessible :name, :email, :bio",
        "attr_accessible :title, :content, :published",
        "attr_protected :admin, :role",
        "attr_protected :is_admin",
        "# attr_accessible :admin # commented out",
        "validates :admin, inclusion: { in: [true, false] }"
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "False positive detected for: #{code}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = DangerousAttrAccessible.vulnerability_metadata()
      
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

    test "vulnerability metadata contains mass assignment specific information" do
      metadata = DangerousAttrAccessible.vulnerability_metadata()
      
      assert String.contains?(String.downcase(metadata.description), "mass assignment")
      assert String.contains?(String.downcase(metadata.attack_vectors), "privilege")
      assert String.contains?(metadata.business_impact, "privilege escalation")
      assert String.contains?(String.downcase(metadata.safe_alternatives), "strong parameters")
      assert String.contains?(metadata.prevention_tips, "Rails 4")
    end

    test "includes AST enhancement rules" do
      enhancement = DangerousAttrAccessible.ast_enhancement()
      
      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has Rails 2/3 specific rules" do
      enhancement = DangerousAttrAccessible.ast_enhancement()
      
      assert enhancement.context_rules.rails_version_checks
      assert enhancement.context_rules.model_indicators
      assert enhancement.ast_rules.attribute_analysis
      assert enhancement.confidence_rules.adjustments.has_dangerous_fields
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = DangerousAttrAccessible.enhanced_pattern()
      
      assert enhanced.id == "rails-dangerous-attr-accessible"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = DangerousAttrAccessible.pattern()
      
      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end

    test "applies to Rails model files" do
      assert DangerousAttrAccessible.applies_to_file?("app/models/user.rb")
      assert DangerousAttrAccessible.applies_to_file?("app/models/admin/post.rb")
      refute DangerousAttrAccessible.applies_to_file?("app/controllers/users_controller.rb")
      refute DangerousAttrAccessible.applies_to_file?("test.js")
    end

    test "applies to ruby files with Rails framework" do
      assert DangerousAttrAccessible.applies_to_file?("model.rb", ["rails"])
      refute DangerousAttrAccessible.applies_to_file?("model.rb", ["sinatra"])
      refute DangerousAttrAccessible.applies_to_file?("model.py", ["rails"])
    end
  end
end