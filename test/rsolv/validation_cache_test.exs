defmodule Rsolv.ValidationCacheTest do
  use Rsolv.DataCase
  alias Rsolv.ValidationCache
  alias Rsolv.ValidationCache.CachedValidation
  alias Rsolv.Customers.ForgeAccount
  alias Rsolv.Customers.Customer
  
  # Helper to create test data
  defp create_forge_account do
    unique_id = System.unique_integer([:positive])
    
    # Create a customer directly
    customer = %Customer{
      name: "Test Customer #{unique_id}", 
      email: "test#{unique_id}@example.com",
      subscription_plan: "trial"
    }
    |> Repo.insert!()
    
    # Create forge account
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
  
  describe "store/1" do
    test "stores validation result with all metadata" do
      forge_account = create_forge_account()
      validation_data = build_validation_data(forge_account)
      
      assert {:ok, cached} = ValidationCache.store(validation_data)
      assert cached.cache_key =~ "sql-injection"
      assert cached.ttl_expires_at
      assert cached.is_false_positive == true
      assert cached.confidence == Decimal.new("0.95")
      assert cached.forge_account_id == to_string(forge_account.id)
    end
    
    test "generates cache key automatically" do
      forge_account = create_forge_account()
      validation_data = build_validation_data(forge_account)
      
      {:ok, cached} = ValidationCache.store(validation_data)
      
      expected_key = "#{forge_account.id}/RSOLV-dev/nodegoat/[app.js:42]:sql-injection"
      assert cached.cache_key == expected_key
    end
    
    test "sets TTL to 90 days from now" do
      forge_account = create_forge_account()
      validation_data = build_validation_data(forge_account)
      
      {:ok, cached} = ValidationCache.store(validation_data)
      
      # Check TTL is approximately 90 days from now (within 1 minute tolerance)
      expected_ttl = DateTime.add(DateTime.utc_now(), 90, :day)
      diff_seconds = DateTime.diff(cached.ttl_expires_at, expected_ttl)
      assert abs(diff_seconds) < 60
    end
    
    test "updates existing cache entry" do
      forge_account = create_forge_account()
      validation_data = build_validation_data(forge_account)
      
      {:ok, original} = ValidationCache.store(validation_data)
      
      # Store again with updated confidence
      updated_data = %{validation_data | confidence: 0.99}
      {:ok, updated} = ValidationCache.store(updated_data)
      
      assert updated.id == original.id
      assert updated.confidence == Decimal.new("0.99")
    end
    
    test "enforces unique cache keys per forge account" do
      forge1 = create_forge_account()
      forge2 = create_forge_account()
      
      data1 = build_validation_data(forge1)
      data2 = build_validation_data(forge2)
      
      {:ok, cache1} = ValidationCache.store(data1)
      {:ok, cache2} = ValidationCache.store(data2)
      
      assert cache1.id != cache2.id
      assert cache1.forge_account_id != cache2.forge_account_id
    end
    
    test "stores multiple locations correctly" do
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
      
      {:ok, cached} = ValidationCache.store(validation_data)
      
      assert length(cached.locations) == 2
      assert cached.file_hashes["lib/db.js"] == "sha256:def456"
    end
    
    test "stores full validation result when provided" do
      forge_account = create_forge_account()
      full_result = %{
        "astContext" => %{
          "inUserInputFlow" => false,
          "hasValidation" => true
        },
        "originalCode" => "db.query(userInput)"
      }
      
      validation_data = build_validation_data(forge_account, %{
        full_result: full_result
      })
      
      {:ok, cached} = ValidationCache.store(validation_data)
      
      assert cached.full_result["astContext"]["hasValidation"] == true
    end
    
    test "validates confidence is between 0 and 1" do
      forge_account = create_forge_account()
      
      invalid_data = build_validation_data(forge_account, %{
        confidence: 1.5
      })
      
      assert {:error, changeset} = ValidationCache.store(invalid_data)
      assert "must be less than or equal to 1" in errors_on(changeset).confidence
    end
  end
end