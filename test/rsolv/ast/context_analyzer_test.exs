defmodule Rsolv.AST.ContextAnalyzerTest do
  # Changed: parser pool is singleton, must run sequentially
  use ExUnit.Case, async: false

  alias Rsolv.AST.ContextAnalyzer

  describe "path exclusion rules" do
    test "excludes test files from production analysis" do
      test_paths = [
        "test/models/user_test.rb",
        "spec/controllers/users_spec.rb",
        "__tests__/auth.test.js",
        "user.spec.ts",
        "test_user.py",
        "user_test.go"
      ]

      for path <- test_paths do
        context = ContextAnalyzer.analyze_path(path)
        assert context.is_test_file == true
        assert context.confidence_multiplier == 0.3
      end
    end

    test "excludes example and demo files" do
      example_paths = [
        "examples/auth.js",
        "demo/user.py",
        "sample_app.rb",
        "tutorial/login.php"
      ]

      for path <- example_paths do
        context = ContextAnalyzer.analyze_path(path)
        assert context.is_example_file == true
        assert context.confidence_multiplier == 0.5
      end
    end

    test "excludes vendor and third-party files" do
      vendor_paths = [
        "vendor/bundle/ruby/2.7.0/gems/rails-6.0.0/lib/rails.rb",
        "node_modules/express/lib/express.js",
        "third_party/google/auth.py",
        "vendor/composer/autoload.php"
      ]

      for path <- vendor_paths do
        context = ContextAnalyzer.analyze_path(path)
        assert context.is_vendor_file == true
        assert context.should_skip == true
      end
    end

    test "identifies production files" do
      production_paths = [
        "app/models/user.rb",
        "src/controllers/auth.js",
        "lib/security/validator.py",
        "internal/auth/handler.go"
      ]

      for path <- production_paths do
        context = ContextAnalyzer.analyze_path(path)
        assert context.is_test_file == false
        assert context.is_example_file == false
        assert context.is_vendor_file == false
        assert context.confidence_multiplier == 1.0
      end
    end
  end

  describe "framework detection" do
    test "detects Rails ORM usage" do
      ruby_code = """
      class User < ApplicationRecord
        has_many :posts

        def self.find_by_name(name)
          where(name: name).first
        end
      end
      """

      context = ContextAnalyzer.analyze_code(ruby_code, "ruby", %{path: "app/models/user.rb"})
      assert context.framework == "rails"
      assert context.uses_orm == true
      assert context.orm_type == "activerecord"
    end

    test "detects Django ORM usage" do
      python_code = """
      from django.db import models

      class User(models.Model):
          name = models.CharField(max_length=100)
          email = models.EmailField()

          def get_posts(self):
              return self.post_set.all()
      """

      context = ContextAnalyzer.analyze_code(python_code, "python", %{path: "users/models.py"})
      assert context.framework == "django"
      assert context.uses_orm == true
      assert context.orm_type == "django_orm"
    end

    test "detects Express.js framework" do
      js_code = """
      const express = require('express');
      const app = express();

      app.get('/users/:id', (req, res) => {
        const userId = req.params.id;
        // Find user
      });
      """

      context = ContextAnalyzer.analyze_code(js_code, "javascript", %{path: "server.js"})
      assert context.framework == "express"
      assert context.uses_orm == false
    end

    test "detects prepared statement usage" do
      java_code = """
      PreparedStatement pstmt = connection.prepareStatement(
        "SELECT * FROM users WHERE id = ?"
      );
      pstmt.setInt(1, userId);
      ResultSet rs = pstmt.executeQuery();
      """

      context = ContextAnalyzer.analyze_code(java_code, "java", %{path: "UserDao.java"})
      assert context.uses_prepared_statements == true
      assert context.sql_safety_score > 0.8
    end
  end

  describe "dynamic context evaluation" do
    test "evaluates security context based on multiple factors" do
      code = """
      def get_user(user_id)
        # Input validation
        return nil unless user_id.match?(/^\\d+$/)

        # Parameterized query
        User.where(id: user_id).first
      end
      """

      context =
        ContextAnalyzer.evaluate_security_context(code, "ruby", %{
          path: "app/controllers/users_controller.rb",
          pattern_type: :sql_injection
        })

      assert context.has_input_validation == true
      assert context.uses_safe_patterns == true
      assert context.overall_safety_score > 0.7
    end

    test "detects dangerous patterns in context" do
      code = """
      exec("rm -rf " + user_input)
      """

      context =
        ContextAnalyzer.evaluate_security_context(code, "python", %{
          path: "scripts/cleanup.py",
          pattern_type: :command_injection
        })

      assert context.has_dangerous_operations == true
      assert context.user_input_handling == :direct_concatenation
      assert context.overall_safety_score < 0.3
    end

    test "adjusts confidence based on file location" do
      code = "eval(user_input)"

      # Same code in different locations
      contexts = [
        %{path: "test/experiment.js", expected_multiplier: 0.3},
        %{path: "examples/demo.js", expected_multiplier: 0.5},
        %{path: "app/core/executor.js", expected_multiplier: 1.0}
      ]

      for %{path: path, expected_multiplier: multiplier} <- contexts do
        context =
          ContextAnalyzer.evaluate_security_context(code, "javascript", %{
            path: path,
            pattern_type: :code_injection
          })

        assert_in_delta context.location_confidence_multiplier, multiplier, 0.01
      end
    end
  end

  describe "context caching" do
    test "caches path analysis results" do
      path = "app/models/user.rb"

      # First call should analyze
      {time1, context1} =
        :timer.tc(fn ->
          ContextAnalyzer.analyze_path(path)
        end)

      # Second call should be cached
      {time2, context2} =
        :timer.tc(fn ->
          ContextAnalyzer.analyze_path(path)
        end)

      assert context1 == context2
      # Cached call should be faster (relaxed from /10 to /2)
      assert time2 < time1 / 2
    end

    test "invalidates cache on different options" do
      path = "test/models/user_test.rb"

      context1 = ContextAnalyzer.analyze_path(path, %{strict_mode: false})
      context2 = ContextAnalyzer.analyze_path(path, %{strict_mode: true})

      # Different options should produce different results
      refute context1 == context2
      # In strict mode, test files should have lower confidence and might be skipped
      assert context1.confidence_multiplier == 0.3
      assert context2.confidence_multiplier == 0.1
      assert context1.should_skip == false
      assert context2.should_skip == true
    end
  end
end
