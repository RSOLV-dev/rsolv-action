defmodule Rsolv.Security.Patterns.Php.PathTraversalTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Php.PathTraversal
  alias Rsolv.Security.Pattern

  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = PathTraversal.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "php-path-traversal"
      assert pattern.name == "Path Traversal"
      assert pattern.severity == :high
      assert pattern.type == :path_traversal
      assert pattern.languages == ["php"]
    end

    test "includes CWE and OWASP references" do
      pattern = PathTraversal.pattern()

      assert pattern.cwe_id == "CWE-22"
      assert pattern.owasp_category == "A01:2021"
    end
  end

  describe "regex matching" do
    setup do
      pattern = PathTraversal.pattern()
      {:ok, pattern: pattern}
    end

    test "matches file_get_contents with user input", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$content = file_get_contents('uploads/' . $_GET['file']);|,
        ~S|$data = file_get_contents($_POST['filename']);|,
        ~S|$result = file_get_contents($dir . $_REQUEST['path']);|,
        ~S|file_get_contents('/data/' . $_COOKIE['file']);|
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end

    test "matches fopen with user input", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$handle = fopen('logs/' . $_GET['file'], 'r');|,
        ~S|$fp = fopen($_POST['path'], 'r');|,
        ~S|fopen('/tmp/' . $_REQUEST['filename'], 'w');|,
        ~S|$file = fopen($_COOKIE['document'], 'r');|
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end

    test "matches include and require with user input", %{pattern: pattern} do
      vulnerable_code = [
        ~S|include './pages/' . $_GET['page'];|,
        ~S|require $_POST['template'] . '.php';|,
        ~S|include_once '/modules/' . $_REQUEST['module'];|,
        ~S|require_once $_COOKIE['script'];|
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end

    test "matches readfile with user input", %{pattern: pattern} do
      vulnerable_code = [
        ~S|readfile('documents/' . $_GET['doc']);|,
        ~S|readfile($_POST['file']);|,
        ~S|$result = readfile('/uploads/' . $_REQUEST['filename']);|
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end

    test "matches various spacing and formatting", %{pattern: pattern} do
      vulnerable_code = [
        ~S|file_get_contents( $_GET['file'] );|,
        ~S|include( './pages/' . $_POST['page'] );|,
        ~S|fopen(  $_REQUEST['path']  , 'r' );|,
        ~S|readfile('/docs/'.$_GET['doc']);|
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end

    test "does not match safe file operations", %{pattern: pattern} do
      safe_code = [
        ~S|$content = file_get_contents('config.php');|,
        ~S|include './templates/header.php';|,
        ~S|$handle = fopen($safe_file, 'r');|,
        ~S|readfile($validated_path);|,
        ~S|$data = json_decode($_POST['data'], true);|
      ]

      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should not match: #{code}"
      end
    end

    test "matches real-world vulnerable patterns", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$template = file_get_contents('./themes/' . $_GET['theme'] . '/template.php');|,
        ~S|include('./lang/' . $_COOKIE['language'] . '.php');|,
        ~S|$config = fopen('./config/' . $_POST['env'] . '.conf', 'r');|,
        ~S|readfile('./downloads/' . $_REQUEST['filename']);|
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
  end

  describe "test_cases/0" do
    test "all positive cases match" do
      pattern = PathTraversal.pattern()
      test_cases = PathTraversal.test_cases()

      for test_case <- test_cases.positive do
        assert Regex.match?(pattern.regex, test_case.code),
               "Failed to match positive case: #{test_case.description}"
      end
    end

    test "negative cases are documented correctly" do
      test_cases = PathTraversal.test_cases()

      assert length(test_cases.negative) > 0

      for test_case <- test_cases.negative do
        assert Map.has_key?(test_case, :code)
        assert Map.has_key?(test_case, :description)
      end
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = PathTraversal.ast_enhancement()

      assert enhancement.min_confidence >= 0.7
      assert length(enhancement.ast_rules) >= 3

      file_functions_rule =
        Enum.find(enhancement.ast_rules, &(&1.type == "file_access_functions"))

      assert file_functions_rule
      assert "file_get_contents" in file_functions_rule.functions
      assert "include" in file_functions_rule.functions

      mitigation_rule = Enum.find(enhancement.ast_rules, &(&1.type == "path_validation"))
      assert mitigation_rule
      assert "basename" in mitigation_rule.functions
      assert "realpath" in mitigation_rule.functions
    end
  end

  describe "pattern metadata" do
    test "has proper OWASP reference" do
      pattern = PathTraversal.pattern()
      assert pattern.owasp_category == "A01:2021"
    end

    test "has educational content" do
      desc = PathTraversal.vulnerability_description()
      assert desc =~ "path traversal"
      assert desc =~ "directory traversal"
      assert desc =~ "file system"
    end

    test "provides safe alternatives" do
      examples = PathTraversal.examples()
      assert Map.has_key?(examples.fixed, "Input validation and basename")
      assert Map.has_key?(examples.fixed, "Allowlist approach")
    end
  end
end
