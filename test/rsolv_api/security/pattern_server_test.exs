defmodule RsolvApi.Security.PatternServerTest do
  use ExUnit.Case, async: false
  alias RsolvApi.Security.PatternServer
  
  setup do
    # PatternServer is started by the application, no need to start it here
    # Just ensure it's available
    assert GenServer.whereis(PatternServer) != nil
    :ok
  end
  
  describe "get_patterns/2" do
    test "returns patterns for valid language and tier" do
      assert {:ok, patterns} = PatternServer.get_patterns("javascript", :public)
      assert is_list(patterns)
      assert length(patterns) > 0
    end
    
    test "caches patterns after first fetch" do
      # First call - cache miss
      {time1, {:ok, patterns1}} = :timer.tc(fn ->
        PatternServer.get_patterns("python", :public)
      end)
      
      # Second call - should be cached
      {time2, {:ok, patterns2}} = :timer.tc(fn ->
        PatternServer.get_patterns("python", :public)
      end)
      
      # Cached call should be much faster
      assert time2 < time1 / 2
      assert patterns1 == patterns2
    end
    
    test "returns different patterns for different tiers" do
      {:ok, public_patterns} = PatternServer.get_patterns("javascript", :public)
      {:ok, protected_patterns} = PatternServer.get_patterns("javascript", :protected)
      {:ok, ai_patterns} = PatternServer.get_patterns("javascript", :ai)
      
      # Each tier should have progressively more patterns
      assert length(public_patterns) < length(protected_patterns)
      assert length(protected_patterns) < length(ai_patterns)
    end
  end
  
  describe "reload_patterns/0" do
    test "reloads all patterns" do
      # Get initial patterns
      {:ok, initial} = PatternServer.get_patterns("ruby", :public)
      
      # Reload
      :ok = PatternServer.reload_patterns()
      
      # Small delay to ensure reload completes
      Process.sleep(100)
      
      # Patterns should still be available
      {:ok, reloaded} = PatternServer.get_patterns("ruby", :public)
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
      
      assert_receive {:cache_hit, %{count: 1}, %{language: "elixir", tier: :public}}
    end
  end
  
  describe "concurrent access" do
    test "handles concurrent pattern requests" do
      # Spawn multiple concurrent requests
      tasks = for i <- 1..100 do
        Task.async(fn ->
          language = Enum.random(["javascript", "python", "ruby", "java"])
          tier = Enum.random([:public, :protected, :ai])
          PatternServer.get_patterns(language, tier)
        end)
      end
      
      # All should complete successfully
      results = Task.await_many(tasks)
      assert Enum.all?(results, fn {:ok, patterns} -> is_list(patterns) end)
    end
  end
end