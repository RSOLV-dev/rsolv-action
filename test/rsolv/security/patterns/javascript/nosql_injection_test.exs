defmodule Rsolv.Security.Patterns.Javascript.NosqlInjectionTest do
  use ExUnit.Case, async: true
  doctest Rsolv.Security.Patterns.Javascript.NosqlInjection

  alias Rsolv.Security.Pattern
  alias Rsolv.Security.Patterns.Javascript.NosqlInjection

  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = NosqlInjection.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "js-nosql-injection"
      assert pattern.name == "NoSQL Injection"
      assert pattern.type == :nosql_injection
      assert pattern.severity == :high
      assert pattern.languages == ["javascript", "typescript"]
      assert pattern.cwe_id == "CWE-943"
      assert pattern.owasp_category == "A03:2021"
    end

    test "pattern has required metadata" do
      pattern = NosqlInjection.pattern()

      assert pattern.description =~ "NoSQL"
      assert pattern.recommendation =~ "Sanitize"
      assert is_map(pattern.test_cases)
      assert is_list(pattern.test_cases.vulnerable)
      assert is_list(pattern.test_cases.safe)
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive vulnerability metadata" do
      metadata = NosqlInjection.vulnerability_metadata()

      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert is_list(metadata.references)
      assert is_list(metadata.attack_vectors)
      assert is_list(metadata.real_world_impact)
      assert is_list(metadata.cve_examples)
      assert is_list(metadata.safe_alternatives)
    end

    test "metadata includes required reference types" do
      metadata = NosqlInjection.vulnerability_metadata()
      references = metadata.references

      assert Enum.any?(references, &(&1.type == :cwe))
      assert Enum.any?(references, &(&1.type == :owasp))
    end
  end

  describe "detection tests" do
    test "detects MongoDB $where injection" do
      pattern = NosqlInjection.pattern()

      vulnerable_code = """
      db.collection.find({
        $where: userInput
      })
      """

      assert Regex.match?(pattern.regex, vulnerable_code)
    end

    test "detects MongoDB query operator injection" do
      pattern = NosqlInjection.pattern()

      vulnerable_codes = [
        ~S|db.users.find({username: req.body.username})|,
        ~S|collection.users.findOne({email: userData})|,
        ~S|db.products.find({price: req.query.maxPrice})|
      ]

      for code <- vulnerable_codes do
        assert Regex.match?(pattern.regex, code), "Should detect: #{code}"
      end
    end

    test "detects MongoDB update operator injection" do
      pattern = NosqlInjection.pattern()

      vulnerable_code = ~S|db.users.update({_id: id}, req.body)|

      assert Regex.match?(pattern.regex, vulnerable_code)
    end

    test "detects Mongoose query building with user input" do
      pattern = NosqlInjection.pattern()

      vulnerable_codes = [
        ~S|User.find(req.query)|,
        ~S|Product.findOne(req.body.filter)|,
        ~S|Model.where(userInput)|
      ]

      for code <- vulnerable_codes do
        assert Regex.match?(pattern.regex, code), "Should detect: #{code}"
      end
    end
  end

  describe "safe code validation" do
    test "does not match safe parameterized queries" do
      pattern = NosqlInjection.pattern()

      safe_codes = [
        ~S|db.users.find({username: sanitize(req.body.username)})|,
        ~S|User.findOne({_id: mongoose.Types.ObjectId(id)})|,
        ~S|db.collection.find({status: 'active'})|,
        ~S|User.find({email: validator.isEmail(email) ? email : null})|
      ]

      for code <- safe_codes do
        refute Regex.match?(pattern.regex, code), "Should not match: #{code}"
      end
    end

    test "does not match queries with proper validation" do
      pattern = NosqlInjection.pattern()

      safe_code = """
      const sanitizedQuery = {
        username: String(req.body.username),
        age: parseInt(req.body.age, 10)
      };
      db.users.find(sanitizedQuery);
      """

      refute Regex.match?(pattern.regex, safe_code)
    end
  end

  describe "applies_to_file?/1" do
    test "applies to JavaScript files" do
      assert NosqlInjection.applies_to_file?("app.js", nil)
      assert NosqlInjection.applies_to_file?("server.mjs", nil)
      assert NosqlInjection.applies_to_file?("routes/api.js", nil)
    end

    test "applies to TypeScript files" do
      assert NosqlInjection.applies_to_file?("app.ts", nil)
      assert NosqlInjection.applies_to_file?("server.tsx", nil)
      assert NosqlInjection.applies_to_file?("src/models/user.ts", nil)
    end

    test "does not apply to non-JS/TS files" do
      refute NosqlInjection.applies_to_file?("style.css", nil)
      refute NosqlInjection.applies_to_file?("app.py", nil)
      refute NosqlInjection.applies_to_file?("Gemfile", nil)
    end
  end

  describe "ast_enhancement/0" do
    test "returns complete AST enhancement structure" do
      enhancement = NosqlInjection.ast_enhancement()

      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
    end

    test "AST rules specify database query patterns" do
      enhancement = NosqlInjection.ast_enhancement()

      assert enhancement.ast_rules.node_type == "CallExpression"
      assert is_list(enhancement.ast_rules.callee_patterns)
      assert is_map(enhancement.ast_rules.query_analysis)
      assert enhancement.ast_rules.query_analysis.has_user_input == true
    end

    test "context rules include validation checks" do
      enhancement = NosqlInjection.ast_enhancement()

      assert is_list(enhancement.context_rules.exclude_paths)
      assert enhancement.context_rules.exclude_if_sanitized == true
      assert enhancement.context_rules.exclude_if_parameterized == true
      assert is_list(enhancement.context_rules.safe_functions)
    end

    test "confidence rules provide appropriate scoring" do
      enhancement = NosqlInjection.ast_enhancement()

      assert is_number(enhancement.confidence_rules.base)
      assert is_map(enhancement.confidence_rules.adjustments)
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "direct_user_input")
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "uses_sanitization")
      assert enhancement.min_confidence == 0.7
    end
  end
end
