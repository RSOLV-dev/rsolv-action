defmodule Rsolv.ValidationCacheIntegrationTest do
  use Rsolv.DataCase
  
  alias Rsolv.ValidationCache
  alias Rsolv.Customers.ForgeAccount
  alias Rsolv.Customers.Customer
  
  import Rsolv.ValidationCacheHelpers
  
  require Logger
  
  # Helper to create test data
  defp create_forge_account do
    unique_id = System.unique_integer([:positive])
    
    customer = %Customer{
      name: "Test Customer #{unique_id}", 
      email: "test#{unique_id}@example.com"
    }
    |> Repo.insert!()
    
    %ForgeAccount{
      forge_type: :github,
      namespace: "test-org-#{unique_id}",
      customer_id: customer.id,
      verified_at: DateTime.utc_now()
    }
    |> Repo.insert!()
  end
  
  describe "complete cache workflow" do
    test "cache miss → validation → cache hit → invalidation → cache miss" do
      forge_account = create_forge_account()
      
      # Step 1: Initial lookup - should be a cache miss
      result1 = ValidationCache.get(
        forge_account.id,
        "RSOLV-dev/nodegoat",
        [%{file_path: "app.js", line: 42}],
        "sql-injection"
      )
      assert {:miss, nil} = result1
      
      # Step 2: Store validation result (simulating AST validation found false positive)
      validation_data = %{
        forge_account_id: forge_account.id,
        repository: "RSOLV-dev/nodegoat",
        locations: [%{file_path: "app.js", line: 42}],
        vulnerability_type: "sql-injection",
        file_hashes: %{"app.js" => "sha256:original"},
        is_false_positive: true,
        confidence: 0.95,
        reason: "No user input flow detected",
        full_result: %{
          "astContext" => %{
            "inUserInputFlow" => false,
            "hasValidation" => true
          }
        }
      }
      
      {:ok, stored} = ValidationCache.store(validation_data)
      assert stored.is_false_positive == true
      
      # Step 3: Second lookup - should be a cache hit
      result2 = ValidationCache.get(
        forge_account.id,
        "RSOLV-dev/nodegoat",
        [%{file_path: "app.js", line: 42}],
        "sql-injection",
        %{"app.js" => "sha256:original"}  # Same hash
      )
      assert {:ok, cached} = result2
      assert cached.id == stored.id
      assert cached.full_result["astContext"]["hasValidation"] == true
      
      # Step 4: File changes - lookup with different hash should invalidate
      result3 = ValidationCache.get(
        forge_account.id,
        "RSOLV-dev/nodegoat",
        [%{file_path: "app.js", line: 42}],
        "sql-injection",
        %{"app.js" => "sha256:modified"}  # Different hash
      )
      assert {:invalidated, nil} = result3
      
      # Step 5: Explicit invalidation
      {:ok, _count} = ValidationCache.invalidate_by_file(
        forge_account.id,
        "RSOLV-dev/nodegoat",
        "app.js"
      )
      
      # Step 6: After invalidation - should be cache miss again
      result4 = ValidationCache.get(
        forge_account.id,
        "RSOLV-dev/nodegoat",
        [%{file_path: "app.js", line: 42}],
        "sql-injection"
      )
      assert {:miss, nil} = result4
    end
    
    test "multiple vulnerabilities in same file with different cache outcomes" do
      forge_account = create_forge_account()
      
      # Store three different vulnerabilities in the same file
      vuln1 = %{
        forge_account_id: forge_account.id,
        repository: "RSOLV-dev/nodegoat",
        locations: [%{file_path: "app.js", line: 10}],
        vulnerability_type: "sql-injection",
        file_hashes: %{"app.js" => "sha256:v1"},
        is_false_positive: true,
        confidence: 0.95,
        reason: "Parameterized query"
      }
      
      vuln2 = %{
        forge_account_id: forge_account.id,
        repository: "RSOLV-dev/nodegoat",
        locations: [%{file_path: "app.js", line: 20}],
        vulnerability_type: "xss",
        file_hashes: %{"app.js" => "sha256:v1"},
        is_false_positive: false,  # Real vulnerability!
        confidence: 0.90,
        reason: "Direct HTML injection"
      }
      
      vuln3 = %{
        forge_account_id: forge_account.id,
        repository: "RSOLV-dev/nodegoat",
        locations: [%{file_path: "app.js", line: 30}],
        vulnerability_type: "eval",
        file_hashes: %{"app.js" => "sha256:v1"},
        is_false_positive: true,
        confidence: 0.85,
        reason: "Static string only"
      }
      
      {:ok, stored1} = ValidationCache.store(vuln1)
      {:ok, stored2} = ValidationCache.store(vuln2)
      {:ok, stored3} = ValidationCache.store(vuln3)
      
      # All three should be retrievable
      {:ok, found1} = ValidationCache.get(forge_account.id, "RSOLV-dev/nodegoat", 
                                          [%{file_path: "app.js", line: 10}], "sql-injection")
      {:ok, found2} = ValidationCache.get(forge_account.id, "RSOLV-dev/nodegoat",
                                          [%{file_path: "app.js", line: 20}], "xss")
      {:ok, found3} = ValidationCache.get(forge_account.id, "RSOLV-dev/nodegoat",
                                          [%{file_path: "app.js", line: 30}], "eval")
      
      assert found1.is_false_positive == true
      assert found2.is_false_positive == false  # Real vulnerability
      assert found3.is_false_positive == true
      
      # Invalidate all entries for the file
      {:ok, count} = ValidationCache.invalidate_by_file(
        forge_account.id,
        "RSOLV-dev/nodegoat",
        "app.js"
      )
      assert count == 3
      
      # All should now be cache misses
      assert {:miss, nil} = ValidationCache.get(forge_account.id, "RSOLV-dev/nodegoat",
                                                [%{file_path: "app.js", line: 10}], "sql-injection")
      assert {:miss, nil} = ValidationCache.get(forge_account.id, "RSOLV-dev/nodegoat",
                                                [%{file_path: "app.js", line: 20}], "xss")
      assert {:miss, nil} = ValidationCache.get(forge_account.id, "RSOLV-dev/nodegoat",
                                                [%{file_path: "app.js", line: 30}], "eval")
    end
    
    test "cross-file vulnerability caching and invalidation" do
      forge_account = create_forge_account()
      
      # Store a multi-file vulnerability (e.g., SQL injection across modules)
      multi_file_vuln = %{
        forge_account_id: forge_account.id,
        repository: "RSOLV-dev/nodegoat",
        locations: [
          %{file_path: "routes/user.js", line: 42},
          %{file_path: "lib/database.js", line: 100}
        ],
        vulnerability_type: "sql-injection",
        file_hashes: %{
          "routes/user.js" => "sha256:user_v1",
          "lib/database.js" => "sha256:db_v1"
        },
        is_false_positive: true,
        confidence: 0.88,
        reason: "Sanitization in database layer"
      }
      
      {:ok, stored} = ValidationCache.store(multi_file_vuln)
      
      # Should be retrievable with locations in any order
      {:ok, found1} = ValidationCache.get(
        forge_account.id,
        "RSOLV-dev/nodegoat",
        [
          %{file_path: "routes/user.js", line: 42},
          %{file_path: "lib/database.js", line: 100}
        ],
        "sql-injection"
      )
      assert found1.id == stored.id
      
      # Even with reversed order (due to sorting in key generation)
      {:ok, found2} = ValidationCache.get(
        forge_account.id,
        "RSOLV-dev/nodegoat",
        [
          %{file_path: "lib/database.js", line: 100},
          %{file_path: "routes/user.js", line: 42}
        ],
        "sql-injection"
      )
      assert found2.id == stored.id
      
      # Changing ANY file in the vulnerability should invalidate
      {:ok, count} = ValidationCache.invalidate_by_file(
        forge_account.id,
        "RSOLV-dev/nodegoat",
        "lib/database.js"
      )
      assert count == 1
      
      # Should now be a cache miss
      assert {:miss, nil} = ValidationCache.get(
        forge_account.id,
        "RSOLV-dev/nodegoat",
        [
          %{file_path: "routes/user.js", line: 42},
          %{file_path: "lib/database.js", line: 100}
        ],
        "sql-injection"
      )
    end
    
    test "TTL expiration workflow" do
      forge_account = create_forge_account()
      
      # Store with normal TTL
      validation_data = %{
        forge_account_id: forge_account.id,
        repository: "RSOLV-dev/nodegoat",
        locations: [%{file_path: "app.js", line: 42}],
        vulnerability_type: "sql-injection",
        file_hashes: %{"app.js" => "sha256:abc"},
        is_false_positive: true,
        confidence: 0.95,
        reason: "Test"
      }
      
      {:ok, stored} = ValidationCache.store(validation_data)
      
      # Should be retrievable initially
      {:ok, _found} = ValidationCache.get(
        forge_account.id,
        "RSOLV-dev/nodegoat",
        [%{file_path: "app.js", line: 42}],
        "sql-injection"
      )
      
      # Manually expire it by updating TTL to past
      from(c in ValidationCache.CachedValidation, where: c.id == ^stored.id)
      |> Repo.update_all(set: [ttl_expires_at: DateTime.add(DateTime.utc_now(), -1, :day)])
      
      # Should now return expired status
      result = ValidationCache.get(
        forge_account.id,
        "RSOLV-dev/nodegoat",
        [%{file_path: "app.js", line: 42}],
        "sql-injection"
      )
      assert {:expired, nil} = result
    end
    
    test "forge account isolation in complete workflow" do
      forge1 = create_forge_account()
      forge2 = create_forge_account()
      
      # Same vulnerability, different forge accounts
      vuln_data = fn forge_account_id ->
        %{
          forge_account_id: forge_account_id,
          repository: "shared/repo",
          locations: [%{file_path: "app.js", line: 42}],
          vulnerability_type: "sql-injection",
          file_hashes: %{"app.js" => "sha256:shared"},
          is_false_positive: true,
          confidence: 0.95,
          reason: "Safe"
        }
      end
      
      # Store for both accounts
      {:ok, stored1} = ValidationCache.store(vuln_data.(forge1.id))
      {:ok, stored2} = ValidationCache.store(vuln_data.(forge2.id))
      
      # Each should only see their own
      {:ok, found1} = ValidationCache.get(forge1.id, "shared/repo",
                                          [%{file_path: "app.js", line: 42}], "sql-injection")
      {:ok, found2} = ValidationCache.get(forge2.id, "shared/repo",
                                          [%{file_path: "app.js", line: 42}], "sql-injection")
      
      assert found1.id == stored1.id
      assert found2.id == stored2.id
      assert found1.id != found2.id
      
      # Invalidating for forge1 shouldn't affect forge2
      {:ok, count} = ValidationCache.invalidate_by_repository(forge1.id, "shared/repo")
      assert count == 1
      
      # forge1 should have cache miss, forge2 should still have cache hit
      assert {:miss, nil} = ValidationCache.get(forge1.id, "shared/repo",
                                                [%{file_path: "app.js", line: 42}], "sql-injection")
      assert {:ok, still_cached} = ValidationCache.get(forge2.id, "shared/repo",
                                                       [%{file_path: "app.js", line: 42}], "sql-injection")
      assert still_cached.id == stored2.id
    end
    
    test "cache statistics tracking" do
      forge_account = create_forge_account()
      
      # Track cache operations
      cache_operations = []
      
      # Miss
      result1 = ValidationCache.get(forge_account.id, "org/repo",
                                    [%{file_path: "app.js", line: 1}], "xss")
      cache_operations = [{:miss, result1} | cache_operations]
      
      # Store
      {:ok, _} = ValidationCache.store(%{
        forge_account_id: forge_account.id,
        repository: "org/repo",
        locations: [%{file_path: "app.js", line: 1}],
        vulnerability_type: "xss",
        file_hashes: %{"app.js" => "sha256:v1"},
        is_false_positive: true,
        confidence: 0.95,
        reason: "Safe"
      })
      
      # Hit
      result2 = ValidationCache.get(forge_account.id, "org/repo",
                                    [%{file_path: "app.js", line: 1}], "xss")
      cache_operations = [{:hit, result2} | cache_operations]
      
      # Invalidated (file change)
      result3 = ValidationCache.get(forge_account.id, "org/repo",
                                    [%{file_path: "app.js", line: 1}], "xss",
                                    %{"app.js" => "sha256:v2"})
      cache_operations = [{:invalidated, result3} | cache_operations]
      
      # Calculate statistics
      stats = Enum.reduce(cache_operations, %{hits: 0, misses: 0, invalidated: 0}, fn
        {:hit, {:ok, _}}, acc -> %{acc | hits: acc.hits + 1}
        {:miss, {:miss, _}}, acc -> %{acc | misses: acc.misses + 1}
        {:invalidated, {:invalidated, _}}, acc -> %{acc | invalidated: acc.invalidated + 1}
        _, acc -> acc
      end)
      
      assert stats.hits == 1
      assert stats.misses == 1
      assert stats.invalidated == 1
      
      # Hit rate calculation
      total_requests = stats.hits + stats.misses + stats.invalidated
      hit_rate = stats.hits / total_requests * 100
      # Use approximate comparison for floating point
      assert_in_delta hit_rate, 100 / 3, 0.01
    end
  end
  
  describe "performance characteristics" do
    test "bulk operations handle large datasets efficiently" do
      forge_account = create_forge_account()
      
      # Store many cache entries
      entries = for i <- 1..100 do
        %{
          forge_account_id: forge_account.id,
          repository: "RSOLV-dev/large-repo",
          locations: [%{file_path: "file#{i}.js", line: i}],
          vulnerability_type: "xss",
          file_hashes: %{"file#{i}.js" => "sha256:#{i}"},
          is_false_positive: true,
          confidence: 0.90,
          reason: "Bulk test #{i}"
        }
      end
      
      # Store all entries
      stored_ids = Enum.map(entries, fn entry ->
        {:ok, stored} = ValidationCache.store(entry)
        stored.id
      end)
      
      assert length(stored_ids) == 100
      
      # Bulk invalidation should be fast
      {time_microseconds, {:ok, count}} = :timer.tc(fn ->
        ValidationCache.invalidate_by_repository(forge_account.id, "RSOLV-dev/large-repo")
      end)
      
      assert count == 100
      # Should complete in under 100ms even with 100 entries
      assert time_microseconds < 100_000
      
      # All should be invalidated
      for i <- 1..100 do
        assert {:miss, nil} = ValidationCache.get(
          forge_account.id,
          "RSOLV-dev/large-repo",
          [%{file_path: "file#{i}.js", line: i}],
          "xss"
        )
      end
    end
    
    test "cache lookups are fast even with many entries" do
      forge_account = create_forge_account()
      
      # Store many entries to create a realistic dataset
      for i <- 1..1000 do
        ValidationCache.store(%{
          forge_account_id: forge_account.id,
          repository: "RSOLV-dev/perf-test",
          locations: [%{file_path: "path/to/file#{i}.js", line: i * 10}],
          vulnerability_type: rem(i, 3) == 0 && "xss" || rem(i, 2) == 0 && "sql-injection" || "eval",
          file_hashes: %{"path/to/file#{i}.js" => "sha256:content#{i}"},
          is_false_positive: rem(i, 2) == 0,
          confidence: 0.5 + rem(i, 50) / 100,
          reason: "Performance test entry #{i}"
        })
      end
      
      # Measure lookup time for an entry in the middle
      {time_microseconds, result} = :timer.tc(fn ->
        ValidationCache.get(
          forge_account.id,
          "RSOLV-dev/perf-test",
          [%{file_path: "path/to/file500.js", line: 5000}],
          "sql-injection"
        )
      end)
      
      assert {:ok, _cached} = result
      # Should complete in under 10ms even with 1000 entries
      assert time_microseconds < 10_000
      
      Logger.info("Cache lookup completed in #{time_microseconds}μs with 1000 entries")
    end
  end
end