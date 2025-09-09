defmodule Rsolv.ValidationCacheRetrievalTest do
  use Rsolv.DataCase
  alias Rsolv.ValidationCache
  alias Rsolv.Customers.ForgeAccount
  alias Rsolv.Customers.Customer
  
  # Helper to create test data
  defp create_forge_account do
    unique_id = System.unique_integer([:positive])
    
    user = %Rsolv.Accounts.User{
      email: "test#{unique_id}@example.com",
      hashed_password: "dummy_hash"
    }
    |> Repo.insert!()
    
    customer = %Customer{
      name: "Test Customer #{unique_id}", 
      email: "test#{unique_id}@example.com",
      subscription_plan: "trial",
      user_id: user.id
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
  
  defp build_validation_data(forge_account, attrs \\ %{}) do
    defaults = %{
      forge_account_id: forge_account.id,
      repository: "RSOLV-dev/nodegoat",
      locations: [%{file_path: "app.js", line: 42}],
      vulnerability_type: "sql-injection",
      file_hashes: %{"app.js" => "sha256:abc123"},
      is_false_positive: true,
      confidence: 0.95,
      reason: "No user input flow detected"
    }
    
    Map.merge(defaults, attrs)
  end
  
  describe "get/4" do
    test "retrieves valid cache entry" do
      forge_account = create_forge_account()
      validation_data = build_validation_data(forge_account)
      {:ok, stored} = ValidationCache.store(validation_data)
      
      result = ValidationCache.get(
        forge_account.id,
        "RSOLV-dev/nodegoat",
        [%{file_path: "app.js", line: 42}],
        "sql-injection"
      )
      
      assert {:ok, cached} = result
      assert cached.id == stored.id
      assert cached.is_false_positive == true
      assert cached.confidence == Decimal.new("0.95")
    end
    
    test "returns miss for non-existent cache entry" do
      forge_account = create_forge_account()
      
      result = ValidationCache.get(
        forge_account.id,
        "nonexistent/repo",
        [%{file_path: "app.js", line: 1}],
        "xss"
      )
      
      assert {:miss, nil} = result
    end
    
    test "returns expired for cache past TTL" do
      forge_account = create_forge_account()
      validation_data = build_validation_data(forge_account)
      
      # Store with past TTL
      past_time = DateTime.add(DateTime.utc_now(), -1, :day)
      {:ok, _stored} = ValidationCache.store(validation_data)
      
      # Manually update the TTL to be expired
      from(c in Rsolv.ValidationCache.CachedValidation,
        where: c.forge_account_id == ^forge_account.id
      )
      |> Repo.update_all(set: [ttl_expires_at: past_time])
      
      result = ValidationCache.get(
        forge_account.id,
        "RSOLV-dev/nodegoat",
        [%{file_path: "app.js", line: 42}],
        "sql-injection"
      )
      
      assert {:expired, nil} = result
    end
    
    test "validates file hashes when provided" do
      forge_account = create_forge_account()
      validation_data = build_validation_data(forge_account)
      {:ok, _stored} = ValidationCache.store(validation_data)
      
      # Get with different file hash
      result = ValidationCache.get(
        forge_account.id,
        "RSOLV-dev/nodegoat",
        [%{file_path: "app.js", line: 42}],
        "sql-injection",
        %{"app.js" => "sha256:different"}
      )
      
      assert {:invalidated, nil} = result
    end
    
    test "succeeds when file hashes match" do
      forge_account = create_forge_account()
      validation_data = build_validation_data(forge_account)
      {:ok, stored} = ValidationCache.store(validation_data)
      
      # Get with matching file hash
      result = ValidationCache.get(
        forge_account.id,
        "RSOLV-dev/nodegoat",
        [%{file_path: "app.js", line: 42}],
        "sql-injection",
        %{"app.js" => "sha256:abc123"}
      )
      
      assert {:ok, cached} = result
      assert cached.id == stored.id
    end
    
    test "handles multiple file locations correctly" do
      forge_account = create_forge_account()
      locations = [
        %{file_path: "app.js", line: 42},
        %{file_path: "lib/db.js", line: 10}
      ]
      
      validation_data = build_validation_data(forge_account, %{
        locations: locations,
        file_hashes: %{
          "app.js" => "sha256:abc123",
          "lib/db.js" => "sha256:def456"
        }
      })
      
      {:ok, stored} = ValidationCache.store(validation_data)
      
      # Should find with same locations (order shouldn't matter due to sorting)
      result = ValidationCache.get(
        forge_account.id,
        "RSOLV-dev/nodegoat",
        Enum.reverse(locations),  # Reverse order to test sorting
        "sql-injection"
      )
      
      assert {:ok, cached} = result
      assert cached.id == stored.id
    end
    
    test "cache is isolated per forge account" do
      forge1 = create_forge_account()
      forge2 = create_forge_account()
      
      # Store for forge1
      validation_data = build_validation_data(forge1)
      {:ok, _stored} = ValidationCache.store(validation_data)
      
      # Try to get with forge2's ID - should miss
      result = ValidationCache.get(
        forge2.id,
        "RSOLV-dev/nodegoat",
        [%{file_path: "app.js", line: 42}],
        "sql-injection"
      )
      
      assert {:miss, nil} = result
    end
    
    test "returns cache metadata in response" do
      forge_account = create_forge_account()
      validation_data = build_validation_data(forge_account)
      {:ok, stored} = ValidationCache.store(validation_data)
      
      result = ValidationCache.get(
        forge_account.id,
        "RSOLV-dev/nodegoat",
        [%{file_path: "app.js", line: 42}],
        "sql-injection"
      )
      
      assert {:ok, cached} = result
      assert cached.cache_key == stored.cache_key
      assert cached.cached_at != nil
      assert cached.ttl_expires_at != nil
    end
  end
end