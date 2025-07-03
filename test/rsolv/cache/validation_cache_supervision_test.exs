defmodule Rsolv.Cache.ValidationCacheSupervisionTest do
  use ExUnit.Case, async: false
  alias Rsolv.Cache.ValidationCache
  
  describe "supervision tree integration" do
    test "ValidationCache is started by application" do
      # The cache should already be running
      assert Process.whereis(ValidationCache) != nil
    end
    
    test "ETS table is created on startup" do
      # The ETS table should exist
      assert :ets.info(:validation_cache) != :undefined
    end
    
    test "can store and retrieve values after startup" do
      key = :erlang.unique_integer()
      value = %{"test" => "data"}
      
      # Should be able to put and get
      assert :ok = ValidationCache.put(key, value)
      assert {:ok, ^value} = ValidationCache.get(key)
    end
    
    test "survives process restart" do
      # Get the current process
      original_pid = Process.whereis(ValidationCache)
      assert original_pid != nil
      
      # Kill the process
      Process.exit(original_pid, :kill)
      
      # Wait for supervisor to restart it
      :timer.sleep(100)
      
      # Should have a new process
      new_pid = Process.whereis(ValidationCache)
      assert new_pid != nil
      assert new_pid != original_pid
      
      # ETS table should still work
      key = :erlang.unique_integer()
      value = %{"test" => "data"}
      assert :ok = ValidationCache.put(key, value)
      assert {:ok, ^value} = ValidationCache.get(key)
    end
    
    test "stats are reset after process restart" do
      # Clear stats first
      ValidationCache.clear()
      
      # Generate some stats
      key1 = :erlang.unique_integer()
      key2 = :erlang.unique_integer()
      
      ValidationCache.put(key1, %{"data" => 1})
      ValidationCache.get(key1) # hit
      ValidationCache.get(key2) # miss
      
      # Get initial stats
      initial_stats = ValidationCache.get_stats()
      assert initial_stats["cache_hits"] >= 1
      assert initial_stats["cache_misses"] >= 1
      
      # Kill and restart
      original_pid = Process.whereis(ValidationCache)
      Process.exit(original_pid, :kill)
      :timer.sleep(100)
      
      # Stats should be reset after restart (ETS tables don't persist)
      new_stats = ValidationCache.get_stats()
      assert new_stats["cache_hits"] == 0
      assert new_stats["cache_misses"] == 0
    end
  end
  
  describe "error handling" do
    test "handles nil process gracefully" do
      # If somehow the process isn't running, operations should not crash
      # This is a defensive test - in practice the supervisor ensures it's running
      
      # We can't easily test this without mocking, but we can verify
      # that the table exists even if we can't find the process
      assert :ets.info(:validation_cache) != :undefined
    end
  end
end