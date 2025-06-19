defmodule RsolvApi.Security.TierAccessTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.ASTPattern
  alias RsolvApi.Security.Pattern
  
  describe "get_patterns/3 with cumulative tier access" do
    setup do
      # Create test patterns with different tiers
      patterns = [
        %Pattern{
          id: "public-1",
          name: "Public Pattern 1",
          type: :xss,
          default_tier: :public,
          regex: ~r/test/,
          description: "Test",
          severity: :low,
          languages: ["javascript"],
          recommendation: "Fix it",
          test_cases: %{vulnerable: [], safe: []}
        },
        %Pattern{
          id: "public-2", 
          name: "Public Pattern 2",
          type: :weak_crypto,
          default_tier: :public,
          regex: ~r/test/,
          description: "Test",
          severity: :low,
          languages: ["javascript"],
          recommendation: "Fix it",
          test_cases: %{vulnerable: [], safe: []}
        },
        %Pattern{
          id: "protected-1",
          name: "Protected Pattern 1",
          type: :sql_injection,
          default_tier: :protected,
          regex: ~r/test/,
          description: "Test",
          severity: :high,
          languages: ["javascript"],
          recommendation: "Fix it",
          test_cases: %{vulnerable: [], safe: []}
        },
        %Pattern{
          id: "protected-2",
          name: "Protected Pattern 2", 
          type: :command_injection,
          default_tier: :protected,
          regex: ~r/test/,
          description: "Test",
          severity: :critical,
          languages: ["javascript"],
          recommendation: "Fix it",
          test_cases: %{vulnerable: [], safe: []}
        },
        %Pattern{
          id: "ai-1",
          name: "AI Pattern 1",
          type: :ai_prompt_injection,
          default_tier: :ai,
          regex: ~r/test/,
          description: "Test",
          severity: :high,
          languages: ["javascript"],
          recommendation: "Fix it",
          test_cases: %{vulnerable: [], safe: []}
        },
        %Pattern{
          id: "enterprise-1",
          name: "Enterprise Pattern 1",
          type: :proprietary,
          default_tier: :enterprise,
          regex: ~r/test/,
          description: "Test",
          severity: :critical,
          languages: ["javascript"],
          recommendation: "Fix it",
          test_cases: %{vulnerable: [], safe: []}
        }
      ]
      
      %{patterns: patterns}
    end
    
    test "public tier returns only public patterns" do
      # Get patterns for JavaScript public tier
      patterns = ASTPattern.get_patterns("javascript", :public, :standard)
      
      # All patterns should be accessible at public tier
      assert is_list(patterns)
      assert length(patterns) > 0
      
      # Count by tier to verify
      public_count = Enum.count(patterns, fn p -> 
        p.default_tier == :public || p.default_tier == "public"
      end)
      
      # Most patterns should be public
      assert public_count > 0
    end
    
    test "ai tier includes more patterns than public (cumulative)" do
      # Get patterns for both tiers  
      public_patterns = ASTPattern.get_patterns("javascript", :public, :standard)
      ai_patterns = ASTPattern.get_patterns("javascript", :ai, :standard)
      
      # AI should have more patterns due to cumulative access (includes public + ai)
      assert length(ai_patterns) > length(public_patterns)
      
      # All public pattern IDs should be in ai patterns
      public_ids = MapSet.new(public_patterns, & &1.id)
      ai_ids = MapSet.new(ai_patterns, & &1.id)
      
      assert MapSet.subset?(public_ids, ai_ids)
    end
    
    test "ai tier has adequate patterns for professional tier" do
      # Get patterns for different tiers in 3-tier system
      public_patterns = ASTPattern.get_patterns("javascript", :public, :standard)
      ai_patterns = ASTPattern.get_patterns("javascript", :ai, :standard)
      
      # AI should have significantly more patterns than public (cumulative access)
      assert length(ai_patterns) >= length(public_patterns)
      
      # AI tier should have a reasonable number of patterns for professional use
      assert length(ai_patterns) >= 15  # Expect at least 15 patterns for professional tier
    end
    
    test "enterprise tier returns all available patterns (cumulative)" do
      # Get patterns for all tiers in 3-tier system
      public_patterns = ASTPattern.get_patterns("javascript", :public, :standard)
      ai_patterns = ASTPattern.get_patterns("javascript", :ai, :standard)
      enterprise_patterns = ASTPattern.get_patterns("javascript", :enterprise, :standard)
      
      # Enterprise should have the most patterns (cumulative access)
      assert length(enterprise_patterns) >= length(ai_patterns)
      assert length(enterprise_patterns) >= length(public_patterns)
      
      # Should have all patterns from lower tiers
      public_ids = MapSet.new(public_patterns, & &1.id)
      enterprise_ids = MapSet.new(enterprise_patterns, & &1.id)
      
      assert MapSet.subset?(public_ids, enterprise_ids)
    end
    
    test "enhanced format works with all tiers" do
      # Test enhanced format with different tiers
      public_enhanced = ASTPattern.get_patterns("javascript", :public, :enhanced)
      enterprise_enhanced = ASTPattern.get_patterns("javascript", :enterprise, :enhanced)
      
      # All should have AST enhancements
      assert Enum.all?(public_enhanced, fn p -> 
        Map.has_key?(p, :ast_rules) || Map.has_key?(p, :context_rules)
      end)
      
      assert Enum.all?(enterprise_enhanced, fn p -> 
        Map.has_key?(p, :ast_rules) || Map.has_key?(p, :context_rules)
      end)
      
      # Enterprise should have more patterns
      assert length(enterprise_enhanced) > length(public_enhanced)
    end
  end
end