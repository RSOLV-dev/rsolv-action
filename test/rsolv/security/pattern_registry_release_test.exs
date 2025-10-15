defmodule Rsolv.Security.PatternRegistryReleaseTest do
  use ExUnit.Case
  alias Rsolv.Security.PatternRegistry

  describe "pattern loading in release environment" do
    test "loads Python patterns without filesystem access" do
      # This test simulates a release environment where .ex files don't exist
      # The current implementation will fail because it relies on File.ls!

      patterns = PatternRegistry.get_patterns_for_language("python")

      # We expect to find patterns like sql-injection-concat
      pattern_ids = Enum.map(patterns, & &1.id)

      assert length(patterns) > 0, "Should load Python patterns in release"
      assert "python-sql-injection-concat" in pattern_ids, "Should include SQL injection pattern"

      assert "python-command-injection-os-system" in pattern_ids,
             "Should include command injection pattern"
    end

    test "loads JavaScript patterns without filesystem access" do
      patterns = PatternRegistry.get_patterns_for_language("javascript")
      pattern_ids = Enum.map(patterns, & &1.id)

      assert length(patterns) > 0, "Should load JavaScript patterns in release"
      assert Enum.any?(pattern_ids, &String.contains?(&1, "sql-injection"))
    end

    test "loads common patterns that apply to all languages" do
      all_patterns = PatternRegistry.get_all_patterns()

      # Common patterns like JWT, weak crypto, or hardcoded secrets should exist
      common_pattern_ids =
        all_patterns
        |> Enum.filter(fn p ->
          String.contains?(p.id, "jwt") ||
            String.contains?(p.id, "hardcoded") ||
            String.contains?(p.id, "secret") ||
            String.contains?(p.id, "weak")
        end)
        |> Enum.map(& &1.id)

      assert length(common_pattern_ids) > 0,
             "Should include common patterns like JWT, weak crypto, or hardcoded secrets"
    end

    test "returns consistent results across multiple calls" do
      # Pattern loading should be deterministic
      patterns1 = PatternRegistry.get_patterns_for_language("python")
      patterns2 = PatternRegistry.get_patterns_for_language("python")

      assert length(patterns1) == length(patterns2)
      assert Enum.sort_by(patterns1, & &1.id) == Enum.sort_by(patterns2, & &1.id)
    end
  end

  describe "get_all_patterns/0" do
    test "loads patterns from all languages without filesystem access" do
      all_patterns = PatternRegistry.get_all_patterns()

      # Group by language to verify we have patterns for each
      by_language =
        all_patterns
        |> Enum.flat_map(fn p ->
          Enum.map(p.languages || [], fn lang -> {lang, p.id} end)
        end)
        |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))

      # We should have patterns for major languages
      assert Map.has_key?(by_language, "python")
      assert Map.has_key?(by_language, "javascript")
      assert Map.has_key?(by_language, "ruby")
      assert Map.has_key?(by_language, "php")

      # Verify we have reasonable counts
      assert length(Map.get(by_language, "python", [])) >= 5
      assert length(Map.get(by_language, "javascript", [])) >= 5
    end

    test "loads PHP patterns specifically" do
      patterns = PatternRegistry.get_patterns_for_language("php")
      pattern_ids = Enum.map(patterns, & &1.id)

      assert length(patterns) > 0, "Should load PHP patterns in release"

      assert Enum.any?(pattern_ids, &String.starts_with?(&1, "php-")),
             "PHP patterns should have php- prefix"
    end
  end
end
