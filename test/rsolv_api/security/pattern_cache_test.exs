defmodule RsolvApi.Security.PatternCacheTest do
  use ExUnit.Case, async: false
  
  alias RsolvApi.Security.PatternCache
  alias RsolvApi.Security.EnhancedPattern
  alias RsolvApi.Security.Pattern
  
  setup do
    # Clear cache before each test
    PatternCache.clear()
    :ok
  end
  
  describe "Pattern caching" do
    test "caches enhanced pattern transformations" do
      pattern = build_test_pattern()
      
      # First call should compute and cache
      result1 = PatternCache.get_or_compute("test_pattern", fn ->
        EnhancedPattern.to_enhanced_api_format(pattern)
      end)
      
      # Second call should return from cache
      result2 = PatternCache.get_or_compute("test_pattern", fn ->
        # This should not be called
        raise "Should not compute again!"
      end)
      
      assert result1 == result2
    end
    
    test "uses different cache keys for different formats" do
      pattern = build_test_pattern()
      
      # Cache enhanced format
      enhanced = PatternCache.get_or_compute("pattern:enhanced", fn ->
        EnhancedPattern.to_enhanced_api_format(pattern)
      end)
      
      # Cache standard format
      standard = PatternCache.get_or_compute("pattern:standard", fn ->
        pattern |> EnhancedPattern.to_pattern() |> Pattern.to_api_format()
      end)
      
      # Results should be different
      assert enhanced[:supports_ast] == true
      refute Map.has_key?(standard, :supports_ast)
    end
    
    test "cache expiration" do
      pattern = build_test_pattern()
      
      # Cache with TTL
      result1 = PatternCache.get_or_compute("expiring", fn ->
        EnhancedPattern.to_enhanced_api_format(pattern)
      end, ttl: 100)  # 100ms TTL
      
      # Should still be cached
      result2 = PatternCache.get_or_compute("expiring", fn ->
        raise "Should be cached!"
      end)
      
      assert result1 == result2
      
      # Wait for expiration
      Process.sleep(150)
      
      # Should recompute after expiration
      result3 = PatternCache.get_or_compute("expiring", fn ->
        Map.put(result1, :recomputed, true)
      end)
      
      assert result3[:recomputed] == true
    end
    
    test "handles cache errors gracefully" do
      # Simulate cache failure by stopping the cache process
      PatternCache.stop()
      
      pattern = build_test_pattern()
      
      # Should still compute the result even if cache fails
      result = PatternCache.get_or_compute("test", fn ->
        EnhancedPattern.to_enhanced_api_format(pattern)
      end)
      
      assert result[:id] == pattern.id
    end
  end
  
  describe "Batch operations" do
    test "caches pattern collections efficiently" do
      patterns = [
        build_test_pattern(id: "pattern1"),
        build_test_pattern(id: "pattern2"),
        build_test_pattern(id: "pattern3")
      ]
      
      # Cache the entire collection
      cached_result = PatternCache.get_or_compute("patterns:javascript:enhanced", fn ->
        Enum.map(patterns, &EnhancedPattern.to_enhanced_api_format/1)
      end)
      
      assert length(cached_result) == 3
      
      # Verify it's actually cached
      result2 = PatternCache.get_or_compute("patterns:javascript:enhanced", fn ->
        raise "Should use cache!"
      end)
      
      assert cached_result == result2
    end
    
    test "invalidates related caches on pattern update" do
      pattern = build_test_pattern()
      
      # Cache multiple related entries
      PatternCache.get_or_compute("pattern:1:enhanced", fn ->
        EnhancedPattern.to_enhanced_api_format(pattern)
      end)
      
      PatternCache.get_or_compute("pattern:1:standard", fn ->
        pattern |> EnhancedPattern.to_pattern() |> Pattern.to_api_format()
      end)
      
      PatternCache.get_or_compute("patterns:javascript", fn ->
        [pattern]
      end)
      
      # Invalidate all related caches
      PatternCache.invalidate_pattern("pattern:1")
      
      # All should recompute
      new_pattern = Map.put(pattern, :name, "Updated Pattern")
      
      result = PatternCache.get_or_compute("pattern:1:enhanced", fn ->
        EnhancedPattern.to_enhanced_api_format(new_pattern)
      end)
      
      assert result[:name] == "Updated Pattern"
    end
  end
  
  describe "Cache statistics" do
    test "tracks cache hit rate" do
      pattern = build_test_pattern()
      
      # Reset stats
      PatternCache.reset_stats()
      
      # First call - miss
      PatternCache.get_or_compute("test", fn ->
        EnhancedPattern.to_enhanced_api_format(pattern)
      end)
      
      # Next 3 calls - hits
      for _ <- 1..3 do
        PatternCache.get_or_compute("test", fn ->
          raise "Should hit cache!"
        end)
      end
      
      stats = PatternCache.get_stats()
      assert stats.hits == 3
      assert stats.misses == 1
      assert stats.hit_rate == 0.75
    end
    
    test "tracks cache size" do
      PatternCache.reset_stats()
      
      # Add multiple entries
      for i <- 1..5 do
        pattern = build_test_pattern(id: "pattern#{i}")
        PatternCache.get_or_compute("pattern:#{i}", fn ->
          EnhancedPattern.to_enhanced_api_format(pattern)
        end)
      end
      
      stats = PatternCache.get_stats()
      assert stats.size == 5
    end
  end
  
  describe "Memory management" do
    test "enforces maximum cache size" do
      # Configure max size
      PatternCache.configure(max_size: 3)
      
      # Add more than max entries
      for i <- 1..5 do
        pattern = build_test_pattern(id: "pattern#{i}")
        PatternCache.get_or_compute("pattern:#{i}", fn ->
          EnhancedPattern.to_enhanced_api_format(pattern)
        end)
      end
      
      stats = PatternCache.get_stats()
      assert stats.size <= 3
    end
    
    test "uses LRU eviction strategy" do
      PatternCache.configure(max_size: 2)
      
      # Add two patterns
      pattern1 = build_test_pattern(id: "pattern1")
      pattern2 = build_test_pattern(id: "pattern2")
      
      PatternCache.get_or_compute("p1", fn ->
        EnhancedPattern.to_enhanced_api_format(pattern1)
      end)
      
      PatternCache.get_or_compute("p2", fn ->
        EnhancedPattern.to_enhanced_api_format(pattern2)
      end)
      
      # Access p1 to make it more recent
      PatternCache.get_or_compute("p1", fn ->
        raise "Should be cached!"
      end)
      
      # Add third pattern - should evict p2
      pattern3 = build_test_pattern(id: "pattern3")
      PatternCache.get_or_compute("p3", fn ->
        EnhancedPattern.to_enhanced_api_format(pattern3)
      end)
      
      # p1 should still be cached
      result = PatternCache.get_or_compute("p1", fn ->
        raise "p1 should still be cached!"
      end)
      assert result[:id] == "pattern1"
      
      # p2 should be evicted
      result = PatternCache.get_or_compute("p2", fn ->
        %{evicted: true}
      end)
      assert result[:evicted] == true
    end
  end
  
  # Helper functions
  
  defp build_test_pattern(overrides \\ []) do
    base = %{
      id: "test-pattern",
      name: "Test Pattern",
      description: "A test pattern",
      type: :sql_injection,
      severity: :high,
      languages: ["javascript"],
      default_tier: :protected,
      recommendation: "Use parameterized queries",
      test_cases: %{
        vulnerable: ["query('SELECT * WHERE id = ' + id)"],
        safe: ["query('SELECT * WHERE id = ?', [id])"]
      },
      regex: ~r/SELECT.*WHERE.*\+/,
      ast_rules: [
        %{
          node_type: :binary_expression,
          properties: %{operator: "+"},
          parent_context: nil,
          child_must_contain: nil
        }
      ]
    }
    
    struct(EnhancedPattern, Enum.into(overrides, base))
  end
end