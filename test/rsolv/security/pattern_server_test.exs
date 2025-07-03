defmodule Rsolv.Security.PatternServerTest do
  use ExUnit.Case, async: false
  alias Rsolv.Security.PatternServer
  
  setup do
    # PatternServer is started by the application, no need to start it here
    # Just ensure it's available
    assert GenServer.whereis(PatternServer) != nil
    :ok
  end
  
  describe "get_patterns/2" do
    test "returns patterns for valid language and tier" do
      assert {:ok, patterns} = PatternServer.get_patterns("javascript")
      assert is_list(patterns)
      assert length(patterns) > 0
    end
    
    test "caches patterns after first fetch" do
      # Use a less common language to reduce chance of cache conflicts
      language = "cobol"
      
      # First call - likely cache miss (unless already loaded)
      {:ok, patterns1} = PatternServer.get_patterns(language)
      
      # Second call - should be cached
      {:ok, patterns2} = PatternServer.get_patterns(language)
      
      # Results should be identical
      assert patterns1 == patterns2
    end
    
    test "returns same patterns regardless of tier parameter (backward compatibility)" do
      {:ok, public_patterns} = PatternServer.get_patterns("javascript", :public)
      {:ok, protected_patterns} = PatternServer.get_patterns("javascript", :protected)
      {:ok, ai_patterns} = PatternServer.get_patterns("javascript", :ai)
      
      # After tier removal, all should return the same patterns
      assert public_patterns == protected_patterns
      assert protected_patterns == ai_patterns
      
      # Should also be same as calling without tier
      {:ok, no_tier_patterns} = PatternServer.get_patterns("javascript")
      assert public_patterns == no_tier_patterns
    end
  end
  
  describe "reload_patterns/0" do
    test "reloads all patterns" do
      # Get initial patterns
      {:ok, initial} = PatternServer.get_patterns("ruby")
      
      # Reload
      :ok = PatternServer.reload_patterns()
      
      # Small delay to ensure reload completes
      Process.sleep(100)
      
      # Patterns should still be available
      {:ok, reloaded} = PatternServer.get_patterns("ruby")
      assert length(reloaded) == length(initial)
    end
  end
  
  describe "get_stats/0" do
    test "returns pattern statistics" do
      stats = PatternServer.get_stats()
      
      assert is_map(stats)
      assert Map.has_key?(stats, :total)
      assert Map.has_key?(stats, :loaded_at)
      assert Map.has_key?(stats, :ets_size)
      assert Map.has_key?(stats, :memory)
      
      assert stats.total > 0
      assert stats.ets_size > 0
    end
  end
  
  describe "telemetry events" do
    setup do
      # Attach telemetry handler for testing
      :telemetry.attach(
        "test-handler",
        [:pattern, :cache, :hit],
        fn _event, measurements, metadata, _config ->
          send(self(), {:cache_hit, measurements, metadata})
        end,
        nil
      )
      
      on_exit(fn -> :telemetry.detach("test-handler") end)
      :ok
    end
    
    test "emits cache hit event on cached access" do
      # First access to populate cache
      PatternServer.get_patterns("elixir", :public)
      
      # Second access should hit cache
      PatternServer.get_patterns("elixir", :public)
      
      # Note: tier is no longer included in telemetry metadata after tier removal
      assert_receive {:cache_hit, %{count: 1}, %{language: "elixir"}}
    end
  end
  
  describe "concurrent access" do
    test "handles concurrent pattern requests" do
      # Spawn multiple concurrent requests
      tasks = for _ <- 1..100 do
        Task.async(fn ->
          language = Enum.random(["javascript", "python", "ruby", "java"])
          PatternServer.get_patterns(language)
        end)
      end
      
      # All should complete successfully
      results = Task.await_many(tasks)
      assert Enum.all?(results, fn {:ok, patterns} -> is_list(patterns) end)
    end
  end
end