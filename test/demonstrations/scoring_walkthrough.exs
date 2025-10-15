# Scoring Algorithm Step-by-Step Walkthrough
# RFC-060-AMENDMENT-001 Phase 1 - Backend
#
# This script demonstrates the internal mechanics of the scoring algorithm
# by walking through each step of the calculation for a specific example.

Mix.install([])

defmodule ScoringWalkthrough do
  @moduledoc """
  Step-by-step walkthrough of the scoring algorithm internals.
  Shows exactly how scores are calculated for educational purposes.
  """

  alias Rsolv.AST.TestScorer

  def run do
    IO.puts("\n" <> String.duplicate("=", 80))
    IO.puts("Scoring Algorithm Step-by-Step Walkthrough")
    IO.puts("RFC-060-AMENDMENT-001 Phase 1 - Backend")
    IO.puts(String.duplicate("=", 80) <> "\n")

    # Example 1: Perfect match
    walkthrough_perfect_match()

    # Example 2: Different prefixes
    walkthrough_different_prefixes()

    # Example 3: Partial match
    walkthrough_partial_match()

    IO.puts("\n" <> String.duplicate("=", 80))
    IO.puts("Walkthrough Complete!")
    IO.puts(String.duplicate("=", 80) <> "\n")
  end

  defp walkthrough_perfect_match do
    section_header("Example 1: Perfect Match (Strongly-Paired Prefixes)")

    vulnerable = "lib/app/services/user_service.ex"
    candidate = "test/app/services/user_service_test.exs"

    IO.puts("Vulnerable File: #{vulnerable}")
    IO.puts("Candidate Test:  #{candidate}")
    IO.puts("")

    # Step 1: Normalize paths
    IO.puts(colorize("Step 1: Normalize Paths", :blue))
    IO.puts("━━━━━━━━━━━━━━━━━━━━━━")
    vuln_segments = String.split(vulnerable, "/")
    cand_segments = String.split(candidate, "/")

    IO.puts("  Vulnerable segments: #{inspect(vuln_segments)}")
    IO.puts("  Candidate segments:  #{inspect(cand_segments)}")
    IO.puts("")

    # Step 2: Remove extensions and test affixes
    IO.puts(colorize("Step 2: Remove Extensions & Test Affixes", :blue))
    IO.puts("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    IO.puts("  Remove '.ex', '.exs' extensions")
    IO.puts("  Remove '_test' suffix from 'user_service_test'")
    IO.puts("")
    IO.puts("  Vulnerable normalized: [\"lib\", \"app\", \"services\", \"user_service\"]")
    IO.puts("  Candidate normalized:  [\"test\", \"app\", \"services\", \"user_service\"]")
    IO.puts("")

    # Step 3: Split directories and filename
    IO.puts(colorize("Step 3: Split Directories from Filename", :blue))
    IO.puts("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    IO.puts("  Vulnerable: dirs=[\"lib\", \"app\", \"services\"], file=\"user_service\"")
    IO.puts("  Candidate:  dirs=[\"test\", \"app\", \"services\"], file=\"user_service\"")
    IO.puts("")

    # Step 4: Calculate file score
    IO.puts(colorize("Step 4: Calculate File Score (0.5 weight)", :blue))
    IO.puts("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    IO.puts("  Files match? \"user_service\" == \"user_service\" → YES")
    IO.puts("  File score: 0.5")
    IO.puts("")

    # Step 5: Remove prefixes
    IO.puts(colorize("Step 5: Remove Known Prefixes", :blue))
    IO.puts("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    IO.puts("  \"lib\" and \"test\" are in @all_prefixes → remove them")
    IO.puts("  Vulnerable dirs: [\"app\", \"services\"]")
    IO.puts("  Candidate dirs:  [\"app\", \"services\"]")
    IO.puts("")

    # Step 6: Jaccard similarity
    IO.puts(colorize("Step 6: Calculate Jaccard Similarity", :blue))
    IO.puts("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    IO.puts("  Set 1: {\"app\", \"services\"}")
    IO.puts("  Set 2: {\"app\", \"services\"}")
    IO.puts("  Intersection: {\"app\", \"services\"} → size = 2")
    IO.puts("  Union: {\"app\", \"services\"} → size = 2")
    IO.puts("  Jaccard: 2/2 = 1.0")
    IO.puts("  Directory base score: 1.0 × 0.5 = 0.5")
    IO.puts("")

    # Step 7: Check for prefix penalty
    IO.puts(colorize("Step 7: Check for Prefix Mismatch Penalty", :blue))
    IO.puts("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    IO.puts("  Normalized dirs match perfectly? YES")
    IO.puts("  Original prefixes: \"lib\" vs \"test\"")
    IO.puts("  Are they strongly-paired? {\"lib\", \"test\"} in @strong_pairs → YES")
    IO.puts("  Penalty: 0.0 (no penalty for strongly-paired prefixes)")
    IO.puts("")

    # Step 8: Final path similarity
    IO.puts(colorize("Step 8: Final Path Similarity Score", :blue))
    IO.puts("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    IO.puts("  File score + Directory score - Penalty")
    IO.puts("  = 0.5 + 0.5 - 0.0")
    IO.puts("  = #{colorize("1.0", :green)}")
    IO.puts("")

    # Step 9: Calculate bonuses
    IO.puts(colorize("Step 9: Calculate Bonuses", :blue))
    IO.puts("━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    IO.puts("  Module match? \"user_service\" == \"user_service\" → YES (+0.3)")

    IO.puts(
      "  Directory structure match? [\"app\", \"services\"] == [\"app\", \"services\"] → YES (+0.2)"
    )

    IO.puts("")

    # Step 10: Final score
    IO.puts(colorize("Step 10: Final Total Score", :blue))
    IO.puts("━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    IO.puts("  Path similarity: 1.0")
    IO.puts("  Module bonus:    +0.3")
    IO.puts("  Directory bonus: +0.2")
    IO.puts("  ─────────────────────")
    IO.puts("  Total: #{colorize("1.5", :green)} (Perfect match!)")
    IO.puts("")

    # Verify with actual calculation
    actual_score = TestScorer.calculate_score(vulnerable, candidate)
    IO.puts("  ✓ Verified: TestScorer.calculate_score = #{actual_score}")
    IO.puts("")
  end

  defp walkthrough_different_prefixes do
    section_header("Example 2: Different Prefixes (src vs test)")

    vulnerable = "src/controllers/api/v1/users_controller.js"
    candidate = "test/controllers/api/v1/users_controller.test.js"

    IO.puts("Vulnerable File: #{vulnerable}")
    IO.puts("Candidate Test:  #{candidate}")
    IO.puts("")

    IO.puts(colorize("Key Steps (abbreviated):", :blue))
    IO.puts("")

    IO.puts("1. After normalization:")
    IO.puts("   Vulnerable: [\"src\", \"controllers\", \"api\", \"v1\", \"users_controller\"]")
    IO.puts("   Candidate:  [\"test\", \"controllers\", \"api\", \"v1\", \"users_controller\"]")
    IO.puts("")

    IO.puts("2. Split directories and filename:")

    IO.puts(
      "   Vulnerable: dirs=[\"src\", \"controllers\", \"api\", \"v1\"], file=\"users_controller\""
    )

    IO.puts(
      "   Candidate:  dirs=[\"test\", \"controllers\", \"api\", \"v1\"], file=\"users_controller\""
    )

    IO.puts("")

    IO.puts("3. File score: 0.5 (match)")
    IO.puts("")

    IO.puts("4. Remove prefixes:")
    IO.puts("   Vulnerable: [\"controllers\", \"api\", \"v1\"]")
    IO.puts("   Candidate:  [\"controllers\", \"api\", \"v1\"]")
    IO.puts("")

    IO.puts("5. Jaccard similarity: 3/3 = 1.0 → Directory base score: 0.5")
    IO.puts("")

    IO.puts("6. Check prefix penalty:")
    IO.puts("   Normalized dirs match? YES")
    IO.puts("   Original prefixes: \"src\" vs \"test\"")
    IO.puts("   Strongly-paired? {\"src\", \"test\"} in @strong_pairs → NO")
    IO.puts("   Both are in @all_prefixes and differ? YES")
    IO.puts("   Penalty: #{colorize("0.01", :yellow)} (small penalty)")
    IO.puts("")

    IO.puts("7. Path similarity: 0.5 + 0.5 - 0.01 = #{colorize("0.99", :green)}")
    IO.puts("")

    IO.puts("8. Bonuses:")
    IO.puts("   Module bonus: +0.3")
    IO.puts("   Directory bonus: +0.2")
    IO.puts("")

    IO.puts("9. Final score: 0.99 + 0.3 + 0.2 = #{colorize("1.49", :green)}")
    IO.puts("")

    actual_score = TestScorer.calculate_score(vulnerable, candidate)

    IO.puts(
      "   ✓ Verified: TestScorer.calculate_score = #{:erlang.float_to_binary(actual_score, decimals: 2)}"
    )

    IO.puts("")
  end

  defp walkthrough_partial_match do
    section_header("Example 3: Partial Match (Different Directories)")

    vulnerable = "src/api/v1/users.js"
    candidate = "test/controllers/users_controller.test.js"

    IO.puts("Vulnerable File: #{vulnerable}")
    IO.puts("Candidate Test:  #{candidate}")
    IO.puts("")

    IO.puts(colorize("Key Steps:", :blue))
    IO.puts("")

    IO.puts("1. After normalization:")
    IO.puts("   Vulnerable: [\"src\", \"api\", \"v1\", \"users\"]")
    IO.puts("   Candidate:  [\"test\", \"controllers\", \"users_controller\"]")
    IO.puts("")

    IO.puts("2. Split:")
    IO.puts("   Vulnerable: dirs=[\"src\", \"api\", \"v1\"], file=\"users\"")
    IO.puts("   Candidate:  dirs=[\"test\", \"controllers\"], file=\"users_controller\"")
    IO.puts("")

    IO.puts("3. File score:")
    IO.puts("   \"users\" != \"users_controller\" → #{colorize("0.0", :red)}")
    IO.puts("")

    IO.puts("4. Remove prefixes:")
    IO.puts("   Vulnerable: [\"api\", \"v1\"]")
    IO.puts("   Candidate:  [\"controllers\"]")
    IO.puts("")

    IO.puts("5. Jaccard similarity:")
    IO.puts("   Intersection: {} → 0")
    IO.puts("   Union: {\"api\", \"v1\", \"controllers\"} → 3")
    IO.puts("   Jaccard: 0/3 = 0.0 → Directory score: 0.0")
    IO.puts("")

    IO.puts("6. Path similarity: 0.0 + 0.0 = #{colorize("0.0", :red)}")
    IO.puts("")

    IO.puts("7. Bonuses:")
    IO.puts("   Module match? \"users\" != \"users_controller\" → NO (0)")
    IO.puts("   Directory match? [\"api\", \"v1\"] != [\"controllers\"] → NO (0)")
    IO.puts("")

    IO.puts("8. Final score: 0.0 + 0 + 0 = #{colorize("0.0", :red)} (Poor match)")
    IO.puts("")

    actual_score = TestScorer.calculate_score(vulnerable, candidate)
    IO.puts("   ✓ Verified: TestScorer.calculate_score = #{actual_score}")
    IO.puts("")

    IO.puts(
      "   #{colorize("→", :yellow)} Frontend should use fallback path or create new test file"
    )

    IO.puts("")
  end

  # Helper functions

  defp section_header(title) do
    IO.puts("\n" <> String.duplicate("─", 80))
    IO.puts(colorize(title, :cyan))
    IO.puts(String.duplicate("─", 80) <> "\n")
  end

  defp colorize(text, :blue), do: "\e[34m#{text}\e[0m"
  defp colorize(text, :cyan), do: "\e[36m#{text}\e[0m"
  defp colorize(text, :green), do: "\e[32m#{text}\e[0m"
  defp colorize(text, :yellow), do: "\e[33m#{text}\e[0m"
  defp colorize(text, :red), do: "\e[31m#{text}\e[0m"
end

# Load the TestScorer module and run the walkthrough
Code.require_file("lib/rsolv/ast/test_scorer.ex")
ScoringWalkthrough.run()
