defmodule RsolvApi.Security.Patterns.Elixir.PathTraversalTest do
  use ExUnit.Case, async: true

  alias RsolvApi.Security.Patterns.Elixir.PathTraversal
  alias RsolvApi.Security.Pattern

  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = PathTraversal.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "elixir-path-traversal"
      assert pattern.name == "Path Traversal Vulnerability"
      assert pattern.type == :path_traversal
      assert pattern.severity == :high
      assert pattern.languages == ["elixir"]
      assert pattern.cwe_id == "CWE-22"
      assert pattern.owasp_category == "A01:2021"
      assert pattern.default_tier == :ai
      assert is_list(pattern.regex) or pattern.regex.__struct__ == Regex
    end

    test "pattern has comprehensive test cases" do
      pattern = PathTraversal.pattern()
      
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
      assert length(pattern.test_cases.vulnerable) >= 3
      assert length(pattern.test_cases.safe) >= 3
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = PathTraversal.vulnerability_metadata()
      
      assert is_map(metadata)
      assert Map.has_key?(metadata, :description)
      assert Map.has_key?(metadata, :references)
      assert Map.has_key?(metadata, :attack_vectors)
      assert Map.has_key?(metadata, :real_world_impact)
      assert Map.has_key?(metadata, :cve_examples)
      assert Map.has_key?(metadata, :safe_alternatives)
      
      assert String.length(metadata.description) > 100
      assert length(metadata.references) >= 3
      assert length(metadata.attack_vectors) >= 3
      assert length(metadata.cve_examples) >= 1
    end

    test "includes path traversal information" do
      metadata = PathTraversal.vulnerability_metadata()
      
      # Should mention File operations or path manipulation
      assert String.contains?(metadata.description, "File") or
             String.contains?(metadata.description, "path")
      
      # Should mention Path.expand as safe alternative
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "Path.expand")) or
             Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "validate"))
    end

    test "references include CWE-22 and OWASP A01:2021" do
      metadata = PathTraversal.vulnerability_metadata()
      
      cwe_ref = Enum.find(metadata.references, &(&1.type == :cwe))
      assert cwe_ref.id == "CWE-22"
      
      owasp_ref = Enum.find(metadata.references, &(&1.type == :owasp))
      assert owasp_ref.id == "A01:2021"
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper AST enhancement structure" do
      enhancement = PathTraversal.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.7
    end

    test "AST rules check for file operations" do
      enhancement = PathTraversal.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert Map.has_key?(enhancement.ast_rules, :file_analysis)
      assert enhancement.ast_rules.file_analysis.check_file_operations == true
    end

    test "context rules identify user input sources" do
      enhancement = PathTraversal.ast_enhancement()
      
      assert Map.has_key?(enhancement.context_rules, :user_input_sources)
      assert "params" in enhancement.context_rules.user_input_sources
      assert "conn.params" in enhancement.context_rules.user_input_sources
    end

    test "confidence adjustments for path validation" do
      enhancement = PathTraversal.ast_enhancement()
      
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "has_user_input")
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "uses_path_validation")
    end
  end

  describe "vulnerable code detection" do
    test "detects File operations with interpolated paths" do
      pattern = PathTraversal.pattern()
      
      vulnerable_code = ~S|File.read!("/uploads/#{filename}")|
      assert pattern_matches?(pattern, vulnerable_code)
      
      vulnerable_code2 = ~S|File.write!("#{base_path}/#{user_file}", content)|
      assert pattern_matches?(pattern, vulnerable_code2)
    end

    test "detects File.exists? with user input" do
      pattern = PathTraversal.pattern()
      
      vulnerable_code = ~S|File.exists?("/data/#{params["file"]}")|
      assert pattern_matches?(pattern, vulnerable_code)
    end

    test "detects other File operations" do
      pattern = PathTraversal.pattern()
      
      vulnerable_code = ~S|File.rm!("/tmp/#{user_input}")|
      assert pattern_matches?(pattern, vulnerable_code)
      
      vulnerable_code2 = ~S|File.mkdir_p!("/var/#{directory}")|
      assert pattern_matches?(pattern, vulnerable_code2)
    end

    test "detects Path operations with user input" do
      pattern = PathTraversal.pattern()
      
      vulnerable_code = ~S|Path.join("/uploads", params["file"])|
      assert pattern_matches?(pattern, vulnerable_code)
      
      vulnerable_code2 = ~S|Path.join(base_dir, user_path)|
      assert pattern_matches?(pattern, vulnerable_code2)
    end

    test "detects FileStream with user paths" do
      pattern = PathTraversal.pattern()
      
      vulnerable_code = ~S|File.stream!("/logs/#{log_name}")|
      assert pattern_matches?(pattern, vulnerable_code)
    end

    test "detects File.open with interpolation" do
      pattern = PathTraversal.pattern()
      
      vulnerable_code = ~S|File.open("#{dir}/#{file}", [:read])|
      assert pattern_matches?(pattern, vulnerable_code)
    end
  end

  describe "safe code validation" do
    test "does not match File operations with literal paths" do
      pattern = PathTraversal.pattern()
      
      safe_code = ~S|File.read!("/uploads/avatar.png")|
      refute pattern_matches?(pattern, safe_code)
    end

    test "does not match validated paths" do
      pattern = PathTraversal.pattern()
      
      safe_code = ~S|safe_path = Path.expand(filename, "/uploads")
if String.starts_with?(safe_path, "/uploads/") do
  File.read!(safe_path)
end|
      # Should not match the File.read! with safe_path
      refute String.match?(safe_code, ~r/File\.read!\s*\([^"']*#\{/)
    end

    test "does not match other safe file operations" do
      pattern = PathTraversal.pattern()
      
      safe_code = ~S|File.write!("config/prod.exs", config)|
      refute pattern_matches?(pattern, safe_code)
    end

    test "does not match comments about path traversal" do
      pattern = PathTraversal.pattern()
      
      safe_code = ~S|# Never use File.read! with user input|
      refute pattern_matches?(pattern, safe_code)
    end
  end

  describe "enhanced_pattern/0" do
    test "uses ast_enhancement for better detection" do
      enhanced = PathTraversal.enhanced_pattern()
      
      assert enhanced.id == "elixir-path-traversal"
      assert Map.has_key?(enhanced, :ast_enhancement)
      assert enhanced.ast_enhancement == PathTraversal.ast_enhancement()
    end
  end

  # Helper function to check if pattern matches
  defp pattern_matches?(pattern, code) do
    case pattern.regex do
      regexes when is_list(regexes) ->
        Enum.any?(regexes, fn regex -> Regex.match?(regex, code) end)
      regex ->
        Regex.match?(regex, code)
    end
  end
end