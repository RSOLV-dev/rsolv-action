defmodule Rsolv.Security.Patterns.Python.DebugTrueTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Python.DebugTrue
  alias Rsolv.Security.Pattern

  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = DebugTrue.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "python-debug-true"
      assert pattern.name == "Debug Mode Enabled"
      assert pattern.severity == :medium
      assert pattern.type == :information_disclosure
      assert pattern.languages == ["python"]
    end

    test "includes CWE and OWASP references" do
      pattern = DebugTrue.pattern()

      assert pattern.cwe_id == "CWE-215"
      assert pattern.owasp_category == "A05:2021"
    end

    # CVE examples are stored in vulnerability_description now
  end

  describe "regex matching" do
    setup do
      pattern = DebugTrue.pattern()
      {:ok, pattern: pattern}
    end

    test "matches direct DEBUG = True", %{pattern: pattern} do
      vulnerable_code = [
        "DEBUG = True",
        "DEBUG=True",
        "DEBUG  =  True",
        "# Settings\nDEBUG = True"
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end

    test "matches settings.DEBUG = True", %{pattern: pattern} do
      vulnerable_code = [
        "settings.DEBUG = True",
        "django.conf.settings.DEBUG = True",
        "app.settings.DEBUG = True"
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end

    test "matches debug in configuration dict", %{pattern: pattern} do
      vulnerable_code = [
        "{'debug': True}",
        "{\"debug\": True}",
        "config = {'debug': True, 'host': '0.0.0.0'}"
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end

    test "matches environment variable with True default", %{pattern: pattern} do
      vulnerable_code = [
        "os.environ.get('DEBUG', True)",
        "os.environ.get(\"DEBUG\", True)",
        "os.environ.get('DEBUG', 'True')",
        "os.environ.get(\"DEBUG\", \"True\")"
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end

    test "matches Flask app.debug = True", %{pattern: pattern} do
      vulnerable_code = [
        "app.debug = True",
        "application.debug = True",
        "flask_app.debug = True"
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end

    test "does not match DEBUG = False", %{pattern: pattern} do
      safe_code = [
        "DEBUG = False",
        "settings.DEBUG = False",
        "{'debug': False}",
        "app.debug = False"
      ]

      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should not match: #{code}"
      end
    end

    test "matches even in comments (AST will filter)", %{pattern: pattern} do
      # Regex patterns can't easily distinguish comments
      # AST analysis handles this in production
      comment_code = [
        "# DEBUG = True",
        "# Don't set DEBUG = True in production"
      ]

      for code <- comment_code do
        # These will match but AST analysis filters them
        assert Regex.match?(pattern.regex, code),
               "Regex matches comments (filtered by AST): #{code}"
      end
    end
  end

  describe "test_cases/0" do
    test "all positive cases match" do
      pattern = DebugTrue.pattern()
      test_cases = DebugTrue.test_cases()

      for test_case <- test_cases.positive do
        assert Regex.match?(pattern.regex, test_case),
               "Failed to match positive case: #{test_case}"
      end
    end

    test "all negative cases don't match" do
      pattern = DebugTrue.pattern()
      test_cases = DebugTrue.test_cases()

      for test_case <- test_cases.negative do
        refute Regex.match?(pattern.regex, test_case),
               "Should not match negative case: #{test_case}"
      end
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = DebugTrue.ast_enhancement()

      assert enhancement.min_confidence == 0.8
      assert length(enhancement.ast_rules) == 2

      file_rule = Enum.find(enhancement.ast_rules, &(&1.type == "file_context"))
      assert "settings/development.py" in file_rule.patterns
      assert "test_settings.py" in file_rule.patterns
      assert file_rule.severity_reduction == :low

      code_rule = Enum.find(enhancement.ast_rules, &(&1.type == "code_context"))
      assert Enum.any?(code_rule.checks, &(&1 =~ "environment"))
    end
  end

  describe "pattern metadata" do
    test "has proper OWASP reference" do
      pattern = DebugTrue.pattern()
      assert pattern.owasp_category == "A05:2021"
    end

    test "has educational content" do
      desc = DebugTrue.vulnerability_description()
      assert desc =~ "Detailed Error Pages"
      assert desc =~ "Django"
      assert desc =~ "Flask"
      assert desc =~ "Werkzeug interactive debugger"
    end

    test "provides safe alternatives" do
      examples = DebugTrue.examples()
      assert Map.has_key?(examples.fixed, "Proper Django production settings")
      assert Map.has_key?(examples.fixed, "Flask with environment-based debug")
    end
  end
end
