defmodule Rsolv.ValidationCacheInvalidationTest do
  use Rsolv.DataCase
  alias Rsolv.ValidationCache
  alias Rsolv.ValidationCache.CachedValidation
  alias Rsolv.Customers.ForgeAccount
  alias Rsolv.Customers.Customer

  # Helper to create test data
  defp create_forge_account do
    unique_id = System.unique_integer([:positive])

    customer =
      %Customer{
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

  describe "invalidate/2" do
    test "marks cache entry as invalidated with reason" do
      forge_account = create_forge_account()
      validation_data = build_validation_data(forge_account)
      {:ok, stored} = ValidationCache.store(validation_data)

      {:ok, invalidated} = ValidationCache.invalidate(stored.id, "file_change")

      assert invalidated.id == stored.id
      assert invalidated.invalidated_at != nil
      assert invalidated.invalidation_reason == "file_change"
    end

    test "accepts different invalidation reasons" do
      forge_account = create_forge_account()

      # Test file_change reason
      {:ok, cache1} =
        ValidationCache.store(
          build_validation_data(forge_account, %{
            vulnerability_type: "xss"
          })
        )

      {:ok, inv1} = ValidationCache.invalidate(cache1.id, "file_change")
      assert inv1.invalidation_reason == "file_change"

      # Test ttl_expired reason
      {:ok, cache2} =
        ValidationCache.store(
          build_validation_data(forge_account, %{
            vulnerability_type: "hardcoded-secret"
          })
        )

      {:ok, inv2} = ValidationCache.invalidate(cache2.id, "ttl_expired")
      assert inv2.invalidation_reason == "ttl_expired"

      # Test manual reason
      {:ok, cache3} =
        ValidationCache.store(
          build_validation_data(forge_account, %{
            vulnerability_type: "eval"
          })
        )

      {:ok, inv3} = ValidationCache.invalidate(cache3.id, "manual")
      assert inv3.invalidation_reason == "manual"
    end

    test "invalidated entries are not returned by get" do
      forge_account = create_forge_account()
      validation_data = build_validation_data(forge_account)
      {:ok, stored} = ValidationCache.store(validation_data)

      # Should find before invalidation
      {:ok, _found} =
        ValidationCache.get(
          forge_account.id,
          "RSOLV-dev/nodegoat",
          [%{file_path: "app.js", line: 42}],
          "sql-injection"
        )

      # Invalidate it
      {:ok, _invalidated} = ValidationCache.invalidate(stored.id, "manual")

      # Should not find after invalidation
      {:miss, nil} =
        ValidationCache.get(
          forge_account.id,
          "RSOLV-dev/nodegoat",
          [%{file_path: "app.js", line: 42}],
          "sql-injection"
        )
    end

    test "returns error for non-existent cache entry" do
      result = ValidationCache.invalidate(999_999, "manual")
      assert {:error, :not_found} = result
    end
  end

  describe "invalidate_by_file/3" do
    test "invalidates all entries containing a specific file" do
      forge_account = create_forge_account()

      # Store multiple cache entries with same file
      {:ok, _cache1} =
        ValidationCache.store(
          build_validation_data(forge_account, %{
            vulnerability_type: "sql-injection",
            locations: [%{file_path: "app.js", line: 42}]
          })
        )

      {:ok, _cache2} =
        ValidationCache.store(
          build_validation_data(forge_account, %{
            vulnerability_type: "xss",
            locations: [%{file_path: "app.js", line: 100}]
          })
        )

      # Store one with different file
      {:ok, cache3} =
        ValidationCache.store(
          build_validation_data(forge_account, %{
            vulnerability_type: "eval",
            locations: [%{file_path: "lib/other.js", line: 10}],
            file_hashes: %{"lib/other.js" => "sha256:xyz"}
          })
        )

      # Invalidate all entries with app.js
      {:ok, count} =
        ValidationCache.invalidate_by_file(
          forge_account.id,
          "RSOLV-dev/nodegoat",
          "app.js"
        )

      assert count == 2

      # Verify app.js entries are invalidated
      {:miss, nil} =
        ValidationCache.get(
          forge_account.id,
          "RSOLV-dev/nodegoat",
          [%{file_path: "app.js", line: 42}],
          "sql-injection"
        )

      # Verify other.js entry is still valid
      {:ok, found} =
        ValidationCache.get(
          forge_account.id,
          "RSOLV-dev/nodegoat",
          [%{file_path: "lib/other.js", line: 10}],
          "eval"
        )

      assert found.id == cache3.id
    end

    test "handles multi-file vulnerabilities correctly" do
      forge_account = create_forge_account()

      # Store multi-file vulnerability
      {:ok, _multi} =
        ValidationCache.store(
          build_validation_data(forge_account, %{
            locations: [
              %{file_path: "app.js", line: 42},
              %{file_path: "lib/db.js", line: 10}
            ],
            file_hashes: %{
              "app.js" => "sha256:abc",
              "lib/db.js" => "sha256:def"
            }
          })
        )

      # Invalidating any file in the vulnerability should invalidate it
      {:ok, count} =
        ValidationCache.invalidate_by_file(
          forge_account.id,
          "RSOLV-dev/nodegoat",
          "lib/db.js"
        )

      assert count == 1

      # Should not find the multi-file entry
      {:miss, nil} =
        ValidationCache.get(
          forge_account.id,
          "RSOLV-dev/nodegoat",
          [
            %{file_path: "app.js", line: 42},
            %{file_path: "lib/db.js", line: 10}
          ],
          "sql-injection"
        )
    end

    test "returns zero when no entries match" do
      forge_account = create_forge_account()

      {:ok, count} =
        ValidationCache.invalidate_by_file(
          forge_account.id,
          "RSOLV-dev/nodegoat",
          "nonexistent.js"
        )

      assert count == 0
    end

    test "respects forge account isolation" do
      forge1 = create_forge_account()
      forge2 = create_forge_account()

      # Store for both forge accounts
      {:ok, _cache1} = ValidationCache.store(build_validation_data(forge1))
      {:ok, cache2} = ValidationCache.store(build_validation_data(forge2))

      # Invalidate only for forge1
      {:ok, count} =
        ValidationCache.invalidate_by_file(
          forge1.id,
          "RSOLV-dev/nodegoat",
          "app.js"
        )

      assert count == 1

      # forge2's cache should still be valid
      {:ok, found} =
        ValidationCache.get(
          forge2.id,
          "RSOLV-dev/nodegoat",
          [%{file_path: "app.js", line: 42}],
          "sql-injection"
        )

      assert found.id == cache2.id
    end
  end

  describe "invalidate_by_repository/2" do
    test "invalidates all entries for a repository" do
      forge_account = create_forge_account()

      # Store entries for multiple repos
      {:ok, _cache1} =
        ValidationCache.store(
          build_validation_data(forge_account, %{
            repository: "RSOLV-dev/nodegoat"
          })
        )

      {:ok, _cache2} =
        ValidationCache.store(
          build_validation_data(forge_account, %{
            repository: "RSOLV-dev/nodegoat",
            vulnerability_type: "xss"
          })
        )

      {:ok, cache3} =
        ValidationCache.store(
          build_validation_data(forge_account, %{
            repository: "RSOLV-dev/other-repo"
          })
        )

      # Invalidate all for nodegoat
      {:ok, count} =
        ValidationCache.invalidate_by_repository(
          forge_account.id,
          "RSOLV-dev/nodegoat"
        )

      assert count == 2

      # Verify other-repo still valid
      {:ok, found} =
        ValidationCache.get(
          forge_account.id,
          "RSOLV-dev/other-repo",
          [%{file_path: "app.js", line: 42}],
          "sql-injection"
        )

      assert found.id == cache3.id
    end
  end
end
