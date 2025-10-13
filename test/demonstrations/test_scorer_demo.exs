# Demonstration: TestScorer Algorithm Behavior
# RFC-060-AMENDMENT-001 Phase 1 - Backend
#
# This script demonstrates how the path similarity scoring algorithm works
# with real-world examples across different languages and frameworks.

Mix.install([])

defmodule TestScorerDemo do
  @moduledoc """
  Interactive demonstration of the TestScorer algorithm.
  Shows scoring behavior for various real-world scenarios.
  """

  alias Rsolv.AST.TestScorer

  def run do
    IO.puts("\n" <> String.duplicate("=", 80))
    IO.puts("TestScorer Algorithm Demonstration")
    IO.puts("RFC-060-AMENDMENT-001 Phase 1 - Backend")
    IO.puts(String.duplicate("=", 80) <> "\n")

    # Scenario 1: Ruby/RSpec - Perfect match with strongly-paired prefixes
    demo_ruby_rspec()

    # Scenario 2: JavaScript/Vitest - Different prefixes
    demo_javascript_vitest()

    # Scenario 3: Python/pytest - Multiple candidates
    demo_python_pytest()

    # Scenario 4: Deep directory structures
    demo_deep_structures()

    # Scenario 5: No good matches - fallback path
    demo_fallback()

    # Scenario 6: Edge case - identical scores
    demo_identical_scores()

    IO.puts("\n" <> String.duplicate("=", 80))
    IO.puts("Demonstration Complete!")
    IO.puts(String.duplicate("=", 80) <> "\n")
  end

  defp demo_ruby_rspec do
    section_header("Scenario 1: Ruby/RSpec - Strongly-Paired Prefixes")

    vulnerable_file = "lib/app/services/user_service.ex"
    candidates = [
      "test/app/services/user_service_test.exs",
      "test/app/models/user_test.exs",
      "test/unit/authentication_test.exs"
    ]

    IO.puts("Vulnerable File: #{vulnerable_file}")
    IO.puts("Framework: rspec")
    IO.puts("\nCandidate Test Files:")

    result = TestScorer.score_test_files(vulnerable_file, candidates, "rspec")

    Enum.each(result.recommendations, fn rec ->
      IO.puts("  #{format_score(rec.score)} - #{rec.path}")
      IO.puts("             Reason: #{rec.reason}")
    end)

    IO.puts("\nFallback Path: #{result.fallback.path}")
    IO.puts("Reason: #{result.fallback.reason}")

    explain_strongly_paired()
  end

  defp demo_javascript_vitest do
    section_header("Scenario 2: JavaScript/Vitest - Different Prefixes")

    vulnerable_file = "src/controllers/api/v1/users_controller.js"
    candidates = [
      "test/controllers/api/v1/users_controller.test.js",
      "test/controllers/users_controller.test.js",
      "test/api/integration_test.js"
    ]

    IO.puts("Vulnerable File: #{vulnerable_file}")
    IO.puts("Framework: vitest")
    IO.puts("\nCandidate Test Files:")

    result = TestScorer.score_test_files(vulnerable_file, candidates, "vitest")

    Enum.each(result.recommendations, fn rec ->
      IO.puts("  #{format_score(rec.score)} - #{rec.path}")
      IO.puts("             Reason: #{rec.reason}")

      # Explain the score
      if rec.score == 0.99 do
        IO.puts("             Note: 0.99 (not 1.0) because 'src' and 'test' aren't strongly-paired")
      end
    end)

    IO.puts("\nFallback Path: #{result.fallback.path}")

    explain_different_prefixes()
  end

  defp demo_python_pytest do
    section_header("Scenario 3: Python/pytest - Multiple Candidates Ranked")

    vulnerable_file = "app/services/authentication.py"
    candidates = [
      "tests/services/test_authentication.py",
      "tests/unit/test_auth.py",
      "tests/integration/test_login_flow.py",
      "tests/test_models.py"
    ]

    IO.puts("Vulnerable File: #{vulnerable_file}")
    IO.puts("Framework: pytest")
    IO.puts("\nCandidate Test Files (ranked by score):")

    result = TestScorer.score_test_files(vulnerable_file, candidates, "pytest")

    Enum.with_index(result.recommendations, 1)
    |> Enum.each(fn {rec, index} ->
      IO.puts("\n  #{index}. #{format_score(rec.score)} - #{rec.path}")
      IO.puts("       Reason: #{rec.reason}")
      explain_score_breakdown(rec.score)
    end)

    explain_ranking()
  end

  defp demo_deep_structures do
    section_header("Scenario 4: Deep Directory Structures")

    vulnerable_file = "lib/rsolv/ast/pattern_matcher.ex"
    candidates = [
      "test/rsolv/ast/pattern_matcher_test.exs",
      "test/rsolv/ast/ast_normalizer_test.exs",
      "test/rsolv/security/patterns_test.exs"
    ]

    IO.puts("Vulnerable File: #{vulnerable_file}")
    IO.puts("Framework: rspec (Elixir conventions)")
    IO.puts("\nCandidate Test Files:")

    result = TestScorer.score_test_files(vulnerable_file, candidates, "rspec")

    Enum.each(result.recommendations, fn rec ->
      IO.puts("  #{format_score(rec.score)} - #{rec.path}")
      IO.puts("             Reason: #{rec.reason}")
    end)

    explain_deep_structures()
  end

  defp demo_fallback do
    section_header("Scenario 5: No Good Matches - Fallback Path")

    vulnerable_file = "src/database/migrations/001_create_users.sql"
    candidates = [
      "test/api/users_test.js",
      "test/models/account_test.js"
    ]

    IO.puts("Vulnerable File: #{vulnerable_file}")
    IO.puts("Framework: jest")
    IO.puts("\nCandidate Test Files:")

    result = TestScorer.score_test_files(vulnerable_file, candidates, "jest")

    Enum.each(result.recommendations, fn rec ->
      IO.puts("  #{format_score(rec.score)} - #{rec.path}")
      IO.puts("             Reason: #{rec.reason}")
    end)

    IO.puts("\n⚠️  No good match found!")
    IO.puts("\nFallback Path: #{result.fallback.path}")
    IO.puts("Reason: #{result.fallback.reason}")

    explain_fallback()
  end

  defp demo_identical_scores do
    section_header("Scenario 6: Identical Scores - Consistent Ordering")

    vulnerable_file = "app/utils/helpers.rb"
    candidates = [
      "spec/unit/calculator_spec.rb",
      "spec/unit/formatter_spec.rb",
      "spec/unit/validator_spec.rb"
    ]

    IO.puts("Vulnerable File: #{vulnerable_file}")
    IO.puts("Framework: rspec")
    IO.puts("\nCandidate Test Files (all with similar low scores):")

    result = TestScorer.score_test_files(vulnerable_file, candidates, "rspec")

    Enum.each(result.recommendations, fn rec ->
      IO.puts("  #{format_score(rec.score)} - #{rec.path}")
      IO.puts("             Reason: #{rec.reason}")
    end)

    explain_identical_scores()
  end

  # Formatting and explanation helpers

  defp section_header(title) do
    IO.puts("\n" <> String.duplicate("-", 80))
    IO.puts(title)
    IO.puts(String.duplicate("-", 80) <> "\n")
  end

  defp format_score(score) do
    score_str = :erlang.float_to_binary(score, decimals: 2)

    color = cond do
      score >= 1.5 -> :green
      score >= 1.0 -> :green
      score >= 0.8 -> :yellow
      score >= 0.5 -> :light_yellow
      true -> :red
    end

    colorize(String.pad_leading(score_str, 4), color)
  end

  defp colorize(text, :green), do: "\e[32m#{text}\e[0m"
  defp colorize(text, :yellow), do: "\e[33m#{text}\e[0m"
  defp colorize(text, :light_yellow), do: "\e[93m#{text}\e[0m"
  defp colorize(text, :red), do: "\e[31m#{text}\e[0m"

  defp explain_score_breakdown(score) do
    cond do
      score >= 1.5 ->
        IO.puts("       Breakdown: 1.0 (path match) + 0.3 (module) + 0.2 (directory) = 1.5")
      score >= 1.2 ->
        IO.puts("       Breakdown: ~1.0 (path match) + 0.3 (module bonus)")
      score >= 1.0 ->
        IO.puts("       Breakdown: 1.0 (perfect path match)")
      score >= 0.8 ->
        IO.puts("       Breakdown: ~0.8-1.0 (high path similarity)")
      true ->
        IO.puts("       Breakdown: <0.8 (limited similarity)")
    end
  end

  defp explain_strongly_paired do
    IO.puts("\n💡 Key Insight:")
    IO.puts("   'lib' and 'test' are strongly-paired prefixes in Ruby/Elixir.")
    IO.puts("   When both are present and directories match perfectly, score = 1.0")
    IO.puts("   This reflects the idiomatic structure of Elixir/Ruby projects.")
  end

  defp explain_different_prefixes do
    IO.puts("\n💡 Key Insight:")
    IO.puts("   'src' and 'test' are NOT strongly-paired prefixes.")
    IO.puts("   Perfect directory match with different prefixes = 0.99")
    IO.puts("   Small penalty distinguishes from truly idiomatic matches.")
  end

  defp explain_ranking do
    IO.puts("\n💡 Key Insight:")
    IO.puts("   Files are ranked by combined score:")
    IO.puts("   - Path similarity (0.0-1.0)")
    IO.puts("   - Module name bonus (+0.3 if matches)")
    IO.puts("   - Directory structure bonus (+0.2 if matches)")
    IO.puts("   Higher scores indicate better integration points.")
  end

  defp explain_deep_structures do
    IO.puts("\n💡 Key Insight:")
    IO.puts("   Deep directory structures (lib/rsolv/ast) are normalized.")
    IO.puts("   After removing prefixes, 'rsolv/ast' is compared for both.")
    IO.puts("   Jaccard similarity ensures fair comparison regardless of depth.")
  end

  defp explain_fallback do
    IO.puts("\n💡 Key Insight:")
    IO.puts("   When no candidate scores well, fallback path is generated:")
    IO.puts("   - Suggests framework-specific directory (test/, spec/, tests/)")
    IO.puts("   - Adds 'security/' subdirectory for clarity")
    IO.puts("   - Preserves directory structure from vulnerable file")
    IO.puts("   - Uses framework-specific naming (_test, _spec, .test)")
  end

  defp explain_identical_scores do
    IO.puts("\n💡 Key Insight:")
    IO.puts("   When multiple files have identical scores:")
    IO.puts("   - Original order is preserved (stable sort)")
    IO.puts("   - Frontend can choose first, or present all options")
    IO.puts("   - Low scores suggest creating new test file instead")
  end
end

# Run the demonstration
Code.require_file("lib/rsolv/ast/test_scorer.ex")
TestScorerDemo.run()
