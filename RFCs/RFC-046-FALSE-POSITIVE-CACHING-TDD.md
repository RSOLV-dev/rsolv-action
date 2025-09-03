# RFC-046: False Positive Caching - TDD Implementation Plan

**Status**: Implementation Complete ✅  
**Created**: 2025-08-16  
**Updated**: 2025-08-17  
**Completed**: 2025-08-17  
**Author**: Platform Team  
**Implements**: RFC-045  

## Summary

Test-Driven Development (TDD) implementation plan for the false positive caching system, following red-green-refactor methodology.

## TDD Cycles

### Cycle 1: Cache Key Generation

#### Red Phase - Write Failing Tests
```elixir
# test/rsolv/validation_cache/key_generator_test.exs
defmodule Rsolv.ValidationCache.KeyGeneratorTest do
  use Rsolv.DataCase
  alias Rsolv.ValidationCache.KeyGenerator
  
  describe "generate_key/4" do
    test "generates key for single-file vulnerability" do
      forge_account = fixture(:forge_account)
      locations = [%{file_path: "app/routes/profile.js", line: 42}]
      
      key = KeyGenerator.generate_key(
        forge_account.id,
        "RSOLV-dev/nodegoat",
        locations,
        "sql-injection"
      )
      
      assert key == "#{forge_account.id}/RSOLV-dev/nodegoat/[app/routes/profile.js:42]:sql-injection"
    end
    
    test "sorts multiple locations alphabetically" do
      forge_account = fixture(:forge_account)
      locations = [
        %{file_path: "lib/db.js", line: 10},
        %{file_path: "api/endpoint.js", line: 30}
      ]
      
      key = KeyGenerator.generate_key(
        forge_account.id,
        "RSOLV-dev/nodegoat",
        locations,
        "sql-injection"
      )
      
      # Should be sorted alphabetically
      assert key == "#{forge_account.id}/RSOLV-dev/nodegoat/[api/endpoint.js:30,lib/db.js:10]:sql-injection"
    end
    
    test "handles special characters in repository names" do
      forge_account = fixture(:forge_account)
      locations = [%{file_path: "index.js", line: 1}]
      
      key = KeyGenerator.generate_key(
        forge_account.id,
        "user-name/repo.with.dots",
        locations,
        "xss"
      )
      
      assert key == "#{forge_account.id}/user-name/repo.with.dots/[index.js:1]:xss"
    end
    
    test "raises on empty locations" do
      forge_account = fixture(:forge_account)
      
      assert_raise ArgumentError, fn ->
        KeyGenerator.generate_key(
          forge_account.id,
          "RSOLV-dev/nodegoat",
          [],
          "sql-injection"
        )
      end
    end
  end
end
```

#### Green Phase - Implement Minimum Code
```elixir
# lib/rsolv/validation_cache/key_generator.ex
defmodule Rsolv.ValidationCache.KeyGenerator do
  def generate_key(forge_account_id, repository, locations, vulnerability_type) do
    if Enum.empty?(locations) do
      raise ArgumentError, "Locations cannot be empty"
    end
    
    sorted_locations = 
      locations
      |> Enum.map(&"#{&1.file_path}:#{&1.line}")
      |> Enum.sort()
      |> Enum.join(",")
    
    "#{forge_account_id}/#{repository}/[#{sorted_locations}]:#{vulnerability_type}"
  end
end
```

#### Refactor Phase
```elixir
# lib/rsolv/validation_cache/key_generator.ex
defmodule Rsolv.ValidationCache.KeyGenerator do
  @moduledoc """
  Generates deterministic cache keys for vulnerability validations.
  """
  
  @doc """
  Generates a cache key for a vulnerability validation result.
  
  ## Examples
      iex> generate_key(123, "org/repo", [%{file_path: "app.js", line: 42}], "xss")
      "123/org/repo/[app.js:42]:xss"
  """
  def generate_key(forge_account_id, repository, locations, vulnerability_type) 
      when is_integer(forge_account_id) and 
           is_binary(repository) and 
           is_list(locations) and 
           is_binary(vulnerability_type) do
    
    validate_locations!(locations)
    
    location_string = format_locations(locations)
    "#{forge_account_id}/#{repository}/[#{location_string}]:#{vulnerability_type}"
  end
  
  defp validate_locations!([]), do: raise(ArgumentError, "Locations cannot be empty")
  defp validate_locations!(locations), do: locations
  
  defp format_locations(locations) do
    locations
    |> Enum.map(&format_single_location/1)
    |> Enum.sort()
    |> Enum.join(",")
  end
  
  defp format_single_location(%{file_path: path, line: line}) do
    "#{path}:#{line}"
  end
end
```

### Cycle 2: Cache Storage

#### Red Phase - Write Failing Tests
```elixir
# test/rsolv/validation_cache_test.exs
defmodule Rsolv.ValidationCacheTest do
  use Rsolv.DataCase
  alias Rsolv.ValidationCache
  
  describe "store/2" do
    test "stores validation result with all metadata" do
      forge_account = fixture(:forge_account)
      validation_data = %{
        forge_account_id: forge_account.id,
        repository: "RSOLV-dev/nodegoat",
        locations: [%{file_path: "app.js", line: 42}],
        vulnerability_type: "sql-injection",
        file_hashes: %{"app.js" => "sha256:abc123"},
        is_false_positive: true,
        confidence: 0.95,
        reason: "No user input flow detected"
      }
      
      assert {:ok, cached} = ValidationCache.store(validation_data)
      assert cached.cache_key =~ "sql-injection"
      assert cached.ttl_expires_at
      assert cached.is_false_positive == true
    end
    
    test "updates existing cache entry" do
      forge_account = fixture(:forge_account)
      validation_data = build_validation_data(forge_account)
      
      {:ok, original} = ValidationCache.store(validation_data)
      
      # Store again with updated confidence
      updated_data = %{validation_data | confidence: 0.99}
      {:ok, updated} = ValidationCache.store(updated_data)
      
      assert updated.id == original.id
      assert updated.confidence == 0.99
    end
    
    test "enforces unique cache keys per forge account" do
      forge1 = fixture(:forge_account)
      forge2 = fixture(:forge_account)
      
      data1 = build_validation_data(forge1)
      data2 = build_validation_data(forge2)
      
      {:ok, cache1} = ValidationCache.store(data1)
      {:ok, cache2} = ValidationCache.store(data2)
      
      assert cache1.id != cache2.id
      assert cache1.forge_account_id != cache2.forge_account_id
    end
  end
end
```

#### Green Phase - Implement Storage
```elixir
# lib/rsolv/validation_cache.ex
defmodule Rsolv.ValidationCache do
  import Ecto.Query
  alias Rsolv.Repo
  alias Rsolv.ValidationCache.{KeyGenerator, CachedValidation}
  
  def store(attrs) do
    cache_key = KeyGenerator.generate_key(
      attrs.forge_account_id,
      attrs.repository,
      attrs.locations,
      attrs.vulnerability_type
    )
    
    attrs_with_key = Map.put(attrs, :cache_key, cache_key)
    attrs_with_ttl = Map.put(attrs_with_key, :ttl_expires_at, 
                              DateTime.add(DateTime.utc_now(), 90, :day))
    
    %CachedValidation{}
    |> CachedValidation.changeset(attrs_with_ttl)
    |> Repo.insert(
      on_conflict: :replace_all,
      conflict_target: :cache_key
    )
  end
end
```

### Cycle 3: Cache Retrieval

#### Red Phase - Write Failing Tests
```elixir
describe "get/4" do
  test "retrieves valid cache entry" do
    forge_account = fixture(:forge_account)
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
  end
  
  test "returns nil for cache miss" do
    forge_account = fixture(:forge_account)
    
    result = ValidationCache.get(
      forge_account.id,
      "nonexistent/repo",
      [%{file_path: "app.js", line: 1}],
      "xss"
    )
    
    assert {:miss, nil} = result
  end
  
  test "returns nil for expired cache" do
    forge_account = fixture(:forge_account)
    validation_data = build_validation_data(forge_account)
    
    # Store with expired TTL
    {:ok, _} = ValidationCache.store(%{validation_data | 
      ttl_expires_at: DateTime.add(DateTime.utc_now(), -1, :day)
    })
    
    result = ValidationCache.get(
      forge_account.id,
      "RSOLV-dev/nodegoat",
      [%{file_path: "app.js", line: 42}],
      "sql-injection"
    )
    
    assert {:expired, nil} = result
  end
  
  test "returns nil for changed file hash" do
    forge_account = fixture(:forge_account)
    validation_data = build_validation_data(forge_account)
    {:ok, _} = ValidationCache.store(validation_data)
    
    # Different file hash
    result = ValidationCache.get(
      forge_account.id,
      "RSOLV-dev/nodegoat",
      [%{file_path: "app.js", line: 42}],
      "sql-injection",
      %{"app.js" => "sha256:different"}
    )
    
    assert {:invalidated, nil} = result
  end
end
```

#### Green Phase - Implement Retrieval
```elixir
def get(forge_account_id, repository, locations, vulnerability_type, file_hashes \\ nil) do
  cache_key = KeyGenerator.generate_key(
    forge_account_id,
    repository,
    locations,
    vulnerability_type
  )
  
  case Repo.get_by(CachedValidation, cache_key: cache_key) do
    nil -> 
      {:miss, nil}
      
    cached ->
      cond do
        DateTime.compare(DateTime.utc_now(), cached.ttl_expires_at) == :gt ->
          {:expired, nil}
          
        file_hashes && !matching_file_hashes?(cached.file_hashes, file_hashes) ->
          invalidate(cached)
          {:invalidated, nil}
          
        true ->
          {:ok, cached}
      end
  end
end
```

### Cycle 4: Cache Invalidation

#### Red Phase - Write Failing Tests
```elixir
describe "invalidate/1" do
  test "marks cache entry as invalidated" do
    forge_account = fixture(:forge_account)
    validation_data = build_validation_data(forge_account)
    {:ok, stored} = ValidationCache.store(validation_data)
    
    {:ok, invalidated} = ValidationCache.invalidate(stored, "file_change")
    
    assert invalidated.invalidated_at != nil
    assert invalidated.invalidation_reason == "file_change"
  end
  
  test "invalidate_by_file/2 invalidates all entries for a file" do
    forge_account = fixture(:forge_account)
    
    # Store multiple validations for same file
    {:ok, cache1} = ValidationCache.store(%{
      build_validation_data(forge_account) | 
      vulnerability_type: "sql-injection"
    })
    
    {:ok, cache2} = ValidationCache.store(%{
      build_validation_data(forge_account) | 
      vulnerability_type: "xss"
    })
    
    # Invalidate all for the file
    {:ok, count} = ValidationCache.invalidate_by_file(
      forge_account.id,
      "RSOLV-dev/nodegoat",
      "app.js"
    )
    
    assert count == 2
  end
end
```

### Cycle 5: Integration Tests

#### Red Phase - Write Full Flow Tests
```elixir
# test/rsolv/validation_cache_integration_test.exs
defmodule Rsolv.ValidationCacheIntegrationTest do
  use Rsolv.DataCase
  
  test "complete cache flow" do
    # Setup
    forge_account = fixture(:forge_account)
    api_key = fixture(:api_key, customer: forge_account.customer)
    
    # First validation - cache miss
    validation_request = %{
      vulnerabilities: [%{
        type: "sql-injection",
        locations: [%{file_path: "app.js", line: 42, is_primary: true}]
      }],
      files: %{
        "app.js" => %{
          content: "const query = 'SELECT * FROM users';",
          hash: "sha256:abc123"
        }
      },
      repository: "RSOLV-dev/nodegoat"
    }
    
    # Should trigger actual validation
    result1 = ValidationService.validate(validation_request, api_key)
    assert result1.stats.cache_hits == 0
    assert result1.validated[0].from_cache == false
    
    # Second validation - cache hit
    result2 = ValidationService.validate(validation_request, api_key)
    assert result2.stats.cache_hits == 1
    assert result2.validated[0].from_cache == true
    assert result2.validated[0].cached_at != nil
    
    # Third validation with changed file - cache invalidated
    changed_request = put_in(
      validation_request,
      [:files, "app.js", :hash],
      "sha256:different"
    )
    
    result3 = ValidationService.validate(changed_request, api_key)
    assert result3.stats.cache_hits == 0
    assert result3.validated[0].from_cache == false
  end
end
```

## Testing Guidelines

### Test Data Builders
```elixir
defmodule Rsolv.ValidationCache.TestHelpers do
  def build_validation_data(forge_account, attrs \\ %{}) do
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
end
```

### Property-Based Tests
```elixir
property "cache keys are deterministic" do
  check all forge_id <- integer(),
            repo <- string(:alphanumeric),
            locations <- list_of(location()),
            vuln_type <- string(:alphanumeric) do
    
    key1 = KeyGenerator.generate_key(forge_id, repo, locations, vuln_type)
    key2 = KeyGenerator.generate_key(forge_id, repo, locations, vuln_type)
    
    assert key1 == key2
  end
end
```

## Performance Tests

```elixir
test "cache lookup performance" do
  # Setup 10,000 cache entries
  forge_account = fixture(:forge_account)
  
  for i <- 1..10_000 do
    ValidationCache.store(%{
      build_validation_data(forge_account) |
      locations: [%{file_path: "file#{i}.js", line: i}]
    })
  end
  
  # Measure lookup time
  {time, result} = :timer.tc(fn ->
    ValidationCache.get(
      forge_account.id,
      "RSOLV-dev/nodegoat",
      [%{file_path: "file5000.js", line: 5000}],
      "sql-injection"
    )
  end)
  
  # Should be under 10ms even with 10k entries
  assert time < 10_000  # microseconds
  assert {:ok, _} = result
end
```

## Database Migration Tests

```elixir
test "migration creates proper indexes" do
  # Run migration
  Ecto.Migrator.run(Repo, migrations_path(), :up, all: true)
  
  # Check indexes exist
  {:ok, result} = Repo.query("""
    SELECT indexname FROM pg_indexes 
    WHERE tablename = 'cached_validations'
  """)
  
  index_names = Enum.map(result.rows, &List.first/1)
  
  assert "idx_cache_key" in index_names
  assert "idx_forge_account" in index_names
  assert "idx_repository" in index_names
  assert "idx_ttl" in index_names
end
```

## Continuous Integration

```yaml
# .github/workflows/test.yml
test-validation-cache:
  runs-on: ubuntu-latest
  services:
    postgres:
      image: postgres:14
      env:
        POSTGRES_PASSWORD: postgres
      options: >-
        --health-cmd pg_isready
        --health-interval 10s
        --health-timeout 5s
        --health-retries 5
  
  steps:
    - uses: actions/checkout@v4
    
    - name: Run cache tests
      run: |
        mix test test/rsolv/validation_cache* --cover
        
    - name: Check coverage
      run: |
        mix coveralls.json
        # Ensure > 95% coverage for cache module
```

## Implementation Order

1. **Day 1**: Cache key generation (Cycle 1)
2. **Day 2**: Storage and schema (Cycle 2)
3. **Day 3**: Retrieval with validation (Cycle 3)
4. **Day 4**: Invalidation logic (Cycle 4)
5. **Day 5**: Integration tests (Cycle 5)
6. **Day 6**: Performance optimization
7. **Day 7**: Production deployment

## Success Criteria

- [x] All unit tests pass (39/39 passing)
- [x] Integration tests demonstrate full flow
- [x] Performance tests show <10ms lookup
- [x] Code coverage >95% for cache modules (100% achieved)
- [x] No breaking changes to existing API
- [ ] Cache hit rate >70% in staging (pending deployment)

## Implementation Progress

### Completed Cycles ✅
- ✅ **Cycle 1**: Cache key generation - 6 tests, strict red-green-refactor
- ✅ **Cycle 2**: Cache storage - 8 tests, discovered upsert edge case
- ✅ **Cycle 3**: Cache retrieval - 8 tests, pipeline refactoring
- ✅ **Cycle 4**: Cache invalidation - 9 tests, JSONB array queries
- ✅ **Cycle 5**: Integration tests - 8 tests, performance validation

### TDD Adherence Notes
- Consistently writing tests first (RED)
- Writing minimal code to pass (GREEN)
- Refactoring only after tests pass (REFACTOR)
- Each refactor maintains 100% test coverage
- Discovered and fixed bugs through tests (ID preservation)