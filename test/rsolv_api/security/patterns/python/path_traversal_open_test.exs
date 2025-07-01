defmodule RsolvApi.Security.Patterns.Python.PathTraversalOpenTest do
  use ExUnit.Case
  alias RsolvApi.Security.Patterns.Python.PathTraversalOpen
  alias RsolvApi.Security.Pattern

  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = PathTraversalOpen.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "python-path-traversal-open"
      assert pattern.name == "Path Traversal via open()"
      assert pattern.type == :path_traversal
      assert pattern.severity == :high
      assert pattern.languages == ["python"]
      assert pattern.cwe_id == "CWE-22"
      assert pattern.owasp_category == "A01:2021"
    end
  end

  describe "vulnerability detection" do
    setup do
      {:ok, pattern: PathTraversalOpen.pattern()}
    end

    test "detects open() with string concatenation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|open("/uploads/" + filename)|,
        ~S|open(base_dir + "/" + user_file)|,
        ~S|open("data/" + request.file)|,
        ~S|with open(path + filename) as f:|,
        ~S|file = open(UPLOAD_DIR + user_input)|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code), 
               "Should match vulnerable code: #{code}"
      end
    end

    test "detects open() with f-strings", %{pattern: pattern} do
      assert Regex.match?(pattern.regex, ~S|open(f"/tmp/{user_file}")|)
      assert Regex.match?(pattern.regex, ~S|with open(f"{base_dir}/{filename}") as f:|)
      assert Regex.match?(pattern.regex, ~S|open(f'/var/log/{log_name}')|)
    end

    test "detects open() with format()", %{pattern: pattern} do
      assert Regex.match?(pattern.regex, ~S|open("/uploads/{}".format(filename))|)
      assert Regex.match?(pattern.regex, ~S|open("{}/{}".format(base_dir, user_file))|)
    end

    test "detects open() with % formatting", %{pattern: pattern} do
      assert Regex.match?(pattern.regex, ~S|open("/uploads/%s" % filename)|)
      assert Regex.match?(pattern.regex, ~S|open("%s/%s" % (base_dir, user_file))|)
    end

    test "detects variable assignment followed by open()", %{pattern: pattern} do
      assert Regex.match?(pattern.regex, ~S|file_path = base_dir + "/" + user_input; open(file_path)|)
      assert Regex.match?(pattern.regex, ~S|path = f"/tmp/{filename}"; open(path)|)
    end

    test "ignores safe open() usage", %{pattern: pattern} do
      safe_code = [
        ~S|open("config.json")|,
        ~S|open("/etc/hosts", "r")|,
        ~S|with open("data.txt") as f:|,
        ~S|safe_name = os.path.basename(filename); open(os.path.join("/uploads", safe_name))|,
        ~S|if os.path.commonpath([base_dir, requested_path]) == base_dir: open(requested_path)|
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code), 
               "Should NOT match safe code: #{code}"
      end
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive vulnerability metadata" do
      metadata = PathTraversalOpen.vulnerability_metadata()
      
      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert is_list(metadata.references)
      assert length(metadata.references) > 0
      assert is_list(metadata.attack_vectors)
      assert length(metadata.attack_vectors) > 0
      assert is_list(metadata.real_world_impact)
      assert is_list(metadata.cve_examples)
      assert is_binary(metadata.detection_notes)
      assert is_list(metadata.safe_alternatives)
    end
  end

  describe "ast_enhancement/0" do
    test "returns AST enhancement rules" do
      enhancement = PathTraversalOpen.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
    end

    test "confidence scoring reduces false positives" do
      enhancement = PathTraversalOpen.ast_enhancement()
      
      assert enhancement.min_confidence == 0.7
      assert enhancement.confidence_rules.base == 0.5
      assert enhancement.confidence_rules.adjustments["has_user_input"] == 0.3
      assert enhancement.confidence_rules.adjustments["in_test_code"] == -1.0
    end
  end

  describe "enhanced_pattern/0" do
    test "uses AST enhancement" do
      enhanced = PathTraversalOpen.enhanced_pattern()
      
      assert enhanced.id == "python-path-traversal-open"
      assert enhanced.ast_rules
      assert enhanced.min_confidence == 0.7
    end
  end

  describe "applies_to_file?/1" do
    test "applies to Python files" do
      assert PathTraversalOpen.applies_to_file?("script.py", nil)
      assert PathTraversalOpen.applies_to_file?("utils/helper.py", nil)
      assert PathTraversalOpen.applies_to_file?("src/main.py", nil)
      
      refute PathTraversalOpen.applies_to_file?("script.js", nil)
      refute PathTraversalOpen.applies_to_file?("config.rb", nil)
      refute PathTraversalOpen.applies_to_file?("README.md", nil)
    end
  end
end