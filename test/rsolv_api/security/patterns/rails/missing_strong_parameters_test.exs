defmodule RsolvApi.Security.Patterns.Rails.MissingStrongParametersTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Rails.MissingStrongParameters
  alias RsolvApi.Security.Pattern

  describe "missing_strong_parameters pattern" do
    test "returns correct pattern structure" do
      pattern = MissingStrongParameters.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "rails-missing-strong-parameters"
      assert pattern.name == "Missing Strong Parameters"
      assert pattern.type == :mass_assignment
      assert pattern.severity == :high
      assert pattern.languages == ["ruby"]
      assert pattern.frameworks == ["rails"]
      assert pattern.default_tier == :protected
      assert pattern.cwe_id == "CWE-915"
      assert pattern.owasp_category == "A01:2021"
      
      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects create/update with direct params" do
      pattern = MissingStrongParameters.pattern()
      
      vulnerable_code = [
        "@user = User.create(params[:user])",
        "@post = Post.update(params[:post])",
        "@article.update_attributes(params[:article])",
        "@profile.assign_attributes(params[:profile])",
        "User.create!(params[:user])",
        "Post.update!(params[:post])"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects ActiveRecord.new with params" do
      pattern = MissingStrongParameters.pattern()
      
      vulnerable_code = [
        "@user = User.new(params[:user])",
        "@post = Post.new(params[:post])",
        "article = Article.new(params[:article])",
        "@comment = Comment.new(params[:comment])"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects dangerous permit!" do
      pattern = MissingStrongParameters.pattern()
      
      vulnerable_code = [
        "params.permit!",
        "params[:user].permit!",
        "user_params.permit!",
        "request.params.permit!"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects insert_all and upsert_all with params" do
      pattern = MissingStrongParameters.pattern()
      
      vulnerable_code = [
        "User.insert_all(params[:users])",
        "Post.upsert_all(params[:posts])",
        "Article.insert_all(params[:articles])",
        "Comment.upsert_all(params[:comments])"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "does not detect safe strong parameters usage" do
      pattern = MissingStrongParameters.pattern()
      
      safe_code = [
        "@user = User.create(user_params)",
        "@post = Post.update(post_params)",
        "params.require(:user).permit(:name, :email)",
        "params.permit(:id, :name)",
        "@user = User.create(params.require(:user).permit(:name))",
        "@post.update(params.require(:post).permit(:title, :body))",
        "def user_params\n  params.require(:user).permit(:name)\nend"
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "False positive detected for: #{code}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = MissingStrongParameters.vulnerability_metadata()
      
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
      metadata = MissingStrongParameters.vulnerability_metadata()
      
      assert String.contains?(String.downcase(metadata.description), "mass assignment")
      assert String.contains?(metadata.attack_vectors, "role")
      assert String.contains?(metadata.business_impact, "privilege escalation")
      assert String.contains?(metadata.safe_alternatives, "permit")
      assert String.contains?(metadata.prevention_tips, "strong parameters")
    end

    test "includes AST enhancement rules" do
      enhancement = MissingStrongParameters.ast_enhancement()
      
      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has mass assignment specific rules" do
      enhancement = MissingStrongParameters.ast_enhancement()
      
      assert enhancement.context_rules.rails_versions
      assert enhancement.context_rules.controller_indicators
      assert enhancement.ast_rules.parameter_analysis
      assert enhancement.confidence_rules.adjustments.strong_params_method_penalty
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = MissingStrongParameters.enhanced_pattern()
      
      assert enhanced.id == "rails-missing-strong-parameters"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = MissingStrongParameters.pattern()
      
      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end

    test "applies to Rails controller files" do
      assert MissingStrongParameters.applies_to_file?("app/controllers/users_controller.rb")
      assert MissingStrongParameters.applies_to_file?("app/controllers/api/v1/posts_controller.rb")
      refute MissingStrongParameters.applies_to_file?("app/models/user.rb")
      refute MissingStrongParameters.applies_to_file?("test.js")
    end

    test "applies to ruby files with Rails framework" do
      assert MissingStrongParameters.applies_to_file?("controller.rb", ["rails"])
      refute MissingStrongParameters.applies_to_file?("controller.rb", ["sinatra"])
      refute MissingStrongParameters.applies_to_file?("controller.py", ["rails"])
    end
  end
end