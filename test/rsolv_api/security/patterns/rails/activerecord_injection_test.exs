defmodule RsolvApi.Security.Patterns.Rails.ActiverecordInjectionTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Rails.ActiverecordInjection
  alias RsolvApi.Security.Pattern

  describe "activerecord_injection pattern" do
    test "returns correct pattern structure" do
      pattern = ActiverecordInjection.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "rails-activerecord-injection"
      assert pattern.name == "ActiveRecord SQL Injection"
      assert pattern.type == :sql_injection
      assert pattern.severity == :critical
      assert pattern.languages == ["ruby"]
      assert pattern.frameworks == ["rails"]
      assert pattern.default_tier == :protected
      assert pattern.cwe_id == "CWE-89"
      assert pattern.owasp_category == "A03:2021"
      
      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects where clause with string interpolation" do
      pattern = ActiverecordInjection.pattern()
      
      vulnerable_code = [
        "User.where(\"name = '\#{params[:name]}'\")",
        "Post.where(\"title = '\#{user_input}'\")",
        "Article.where(\"status = '\#{params[:status]}'\")",
        "Comment.where(\"user_id = \#{params[:id]}\")",
        "@users = User.where(\"role = '\#{params[:role]}'\")",
        "Product.where(\"price > \#{params[:min_price]}\")"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects joins with string interpolation" do
      pattern = ActiverecordInjection.pattern()
      
      vulnerable_code = [
        "User.joins(\"LEFT JOIN posts ON posts.user_id = users.id AND posts.status = '\#{params[:status]}'\")",
        "Post.joins(\"INNER JOIN users ON users.id = \#{params[:user_id]}\")",
        "Article.joins(\"JOIN categories ON categories.name = '\#{params[:category]}'\")"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects other ActiveRecord methods with interpolation" do
      pattern = ActiverecordInjection.pattern()
      
      vulnerable_code = [
        "User.group(\"status = '\#{params[:status]}'\")",
        "Post.having(\"count > \#{params[:count]}\")",
        "Article.order(\"\#{params[:sort_field]} DESC\")",
        "Comment.select(\"id, \#{params[:fields]}\")",
        "Product.exists?([\"name = '\#{params[:name]}'\")",
        "User.update_all(\"admin = \#{params[:admin]}\")",
        "Post.delete_all(\"user_id = \#{params[:user_id]}\")"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects find_by_sql and count_by_sql with interpolation" do
      pattern = ActiverecordInjection.pattern()
      
      vulnerable_code = [
        "User.find_by_sql(\"SELECT * FROM users WHERE name = '\#{params[:name]}'\")",
        "Post.find_by_sql(\"SELECT * FROM posts WHERE id = \#{params[:id]}\")",
        "User.count_by_sql(\"SELECT COUNT(*) FROM users WHERE role = '\#{params[:role]}'\")",
        "Article.count_by_sql(\"SELECT COUNT(*) FROM articles WHERE status = '\#{status}'\")"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "detects various quote styles with interpolation" do
      pattern = ActiverecordInjection.pattern()
      
      vulnerable_code = [
        "User.where(\"name = '\#{name}'\")",     # Double quotes
        "User.where('name = \"\#{name}\"')",     # Single quotes (should still match)
        "User.where(`name = '\#{name}'`)",       # Backticks
        "User.where(\"\"\"name = '\#{name}'\"\"\")" # Triple quotes
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Failed to detect: #{code}"
      end
    end

    test "does not detect safe parameterized queries" do
      pattern = ActiverecordInjection.pattern()
      
      safe_code = [
        "User.where(\"name = ?\", params[:name])",
        "Post.where(\"title = ? AND status = ?\", title, status)",
        "Article.where(name: params[:name])",
        "Comment.where(user_id: params[:user_id])",
        "User.where(:name => params[:name])",
        "Product.where(\"price > :price\", price: params[:price])",
        "User.find_by(name: params[:name])",
        "Post.find_by_name(params[:name])"
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "False positive detected for: #{code}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = ActiverecordInjection.vulnerability_metadata()
      
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

    test "vulnerability metadata contains SQL injection specific information" do
      metadata = ActiverecordInjection.vulnerability_metadata()
      
      assert String.contains?(String.downcase(metadata.description), "sql injection")
      assert String.contains?(String.downcase(metadata.attack_vectors), "database")
      assert String.contains?(metadata.business_impact, "data breach")
      assert String.contains?(metadata.safe_alternatives, "parameterized")
      assert String.contains?(metadata.prevention_tips, "interpolation")
    end

    test "includes AST enhancement rules" do
      enhancement = ActiverecordInjection.ast_enhancement()
      
      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has SQL injection specific rules" do
      enhancement = ActiverecordInjection.ast_enhancement()
      
      assert enhancement.context_rules.input_sources
      assert enhancement.context_rules.activerecord_methods
      assert enhancement.ast_rules.interpolation_detection
      assert enhancement.confidence_rules.adjustments.direct_user_input
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = ActiverecordInjection.enhanced_pattern()
      
      assert enhanced.id == "rails-activerecord-injection"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = ActiverecordInjection.pattern()
      
      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end

    test "applies to Rails files" do
      assert ActiverecordInjection.applies_to_file?("app/controllers/users_controller.rb")
      assert ActiverecordInjection.applies_to_file?("app/models/user.rb")
      assert ActiverecordInjection.applies_to_file?("lib/query_builder.rb", ["rails"])
      refute ActiverecordInjection.applies_to_file?("test.js")
      refute ActiverecordInjection.applies_to_file?("script.py")
    end

    test "applies to ruby files with Rails framework" do
      assert ActiverecordInjection.applies_to_file?("query.rb", ["rails"])
      refute ActiverecordInjection.applies_to_file?("query.rb", ["sinatra"])
      refute ActiverecordInjection.applies_to_file?("query.py", ["rails"])
    end
  end
end