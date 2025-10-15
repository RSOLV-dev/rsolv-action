defmodule Rsolv.Security.TierRemovalTest do
  use ExUnit.Case

  alias Rsolv.Security.Pattern
  alias Rsolv.Security.ASTPattern

  describe "Pattern struct without tiers (TDD)" do
    test "Pattern struct should not require default_tier field" do
      # This test should fail initially, then pass after we remove the field
      pattern = %Pattern{
        id: "test-pattern",
        name: "Test Pattern",
        description: "A test pattern without tiers",
        type: :sql_injection,
        severity: :high,
        languages: ["javascript"],
        regex: ~r/test/,
        recommendation: "Fix the issue",
        test_cases: %{
          vulnerable: ["bad code"],
          safe: ["good code"]
        }
        # NOTE: No default_tier field
      }

      # Pattern should be valid without default_tier
      assert Pattern.valid?(pattern)
    end

    test "Pattern.to_api_format should not include tier field" do
      pattern = %Pattern{
        id: "test-pattern",
        name: "Test Pattern",
        description: "A test pattern",
        type: :sql_injection,
        severity: :high,
        languages: ["javascript"],
        regex: ~r/test/,
        recommendation: "Fix it",
        test_cases: %{
          vulnerable: ["bad"],
          safe: ["good"]
        }
      }

      api_format = Pattern.to_api_format(pattern)

      # Should not include tier in the output
      refute Map.has_key?(api_format, :tier)
      refute Map.has_key?(api_format, :default_tier)
    end

    test "Pattern validation should not check tier" do
      # Test that valid_tier? function is removed/not called
      pattern = %Pattern{
        id: "test-pattern",
        name: "Test Pattern",
        description: "A test pattern",
        type: :sql_injection,
        severity: :high,
        languages: ["javascript"],
        regex: ~r/test/,
        recommendation: "Fix it",
        test_cases: %{
          vulnerable: ["bad"],
          safe: ["good"]
        }
      }

      # Should be valid without any tier field
      assert Pattern.valid?(pattern)
    end
  end

  describe "Security module without tier filtering" do
    test "list_patterns_by_language should return all patterns" do
      # This should no longer filter by tier
      patterns = Rsolv.Security.list_patterns_by_language("javascript")

      # Should return all JavaScript patterns regardless of tier
      assert length(patterns) > 20

      # None should have tier information
      Enum.each(patterns, fn pattern ->
        api_format = Pattern.to_api_format(pattern)
        refute Map.has_key?(api_format, :tier)
      end)
    end
  end
end
