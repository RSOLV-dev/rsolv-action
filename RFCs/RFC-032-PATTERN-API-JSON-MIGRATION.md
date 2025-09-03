# RFC-032: Pattern API JSON Migration

**Status**: Draft  
**Created**: June 28, 2025  
**Author**: Infrastructure Team  

## Summary

Migrate the Pattern API from Jason to Elixir 1.18's native JSON support to enable enhanced pattern format, which is currently broken due to regex encoding issues.

## Motivation

The Pattern API's enhanced format provides critical vulnerability detection capabilities including:
- AST rules for precise code structure analysis
- Context rules for false positive prevention  
- Confidence scoring for intelligent filtering

Currently, these features are unavailable because Jason cannot encode Elixir regex objects (`~r/.../`), causing 500 errors. This forces us to use only the standard format, operating at ~50% capability with 65-100% false positive rates for common patterns.

## Detailed Design

### 1. Replace Jason with Native JSON

Elixir 1.18+ includes native JSON support that should handle regex serialization:

```elixir
# Before (Jason)
defp encode_pattern(pattern) do
  Jason.encode!(pattern)  # Fails on regex objects
end

# After (Native JSON)
defp encode_pattern(pattern) do
  pattern
  |> prepare_for_json()  # Convert regex to strings
  |> JSON.encode!()
end
```

### 2. Regex Serialization Strategy

Convert regex objects to a serializable format:

```elixir
defp prepare_for_json(pattern) when is_map(pattern) do
  pattern
  |> Enum.map(fn
    {key, %Regex{} = regex} -> 
      {key, %{
        type: "regex",
        pattern: Regex.source(regex),
        options: Regex.opts(regex)
      }}
    {key, value} when is_map(value) -> 
      {key, prepare_for_json(value)}
    {key, value} when is_list(value) ->
      {key, Enum.map(value, &prepare_for_json/1)}
    {key, value} -> 
      {key, value}
  end)
  |> Map.new()
end
```

### 3. Client-Side Regex Reconstruction

Update the TypeScript client to reconstruct regex from the serialized format:

```typescript
function reconstructPattern(pattern: any): any {
  if (pattern?.type === 'regex') {
    // Convert to JavaScript RegExp
    return new RegExp(pattern.pattern, pattern.options);
  }
  // Recursive handling for nested objects/arrays
  if (typeof pattern === 'object') {
    return Object.entries(pattern).reduce((acc, [key, value]) => {
      acc[key] = reconstructPattern(value);
      return acc;
    }, Array.isArray(pattern) ? [] : {});
  }
  return pattern;
}
```

### 4. Migration Steps

1. **Update Dependencies**: Remove Jason, ensure Elixir >= 1.18
2. **Implement Regex Serialization**: Add prepare_for_json/1 function
3. **Update All Encoders**: Replace Jason.encode with JSON.encode
4. **Update Pattern Controller**: Use new encoding for enhanced format
5. **Update TypeScript Client**: Add regex reconstruction
6. **Test All Patterns**: Ensure enhanced format works E2E
7. **Performance Testing**: Verify no degradation

## Alternatives Considered

1. **Keep Regex as Strings in Patterns**: Would require rewriting all 100+ patterns
2. **Custom Jason Encoder**: Complex and brittle, doesn't leverage native support
3. **Remove Enhanced Format**: Would permanently operate at reduced capability

## Implementation Plan

### Phase 1: Core Migration (Week 1)
- [ ] Remove Jason dependency
- [ ] Implement regex serialization  
- [ ] Update pattern controller
- [ ] Basic testing

### Phase 2: Client Updates (Week 2)
- [ ] Update TypeScript pattern client
- [ ] Add regex reconstruction
- [ ] Integration testing

### Phase 3: Validation (Week 3)
- [ ] Test all enhanced patterns
- [ ] Measure false positive reduction
- [ ] Performance benchmarking
- [ ] Rollout plan

## Success Metrics

1. **Enhanced Format Working**: 0 errors when requesting enhanced patterns
2. **False Positive Reduction**: 65-90% reduction based on pattern type
3. **Performance**: No degradation in response times
4. **All Patterns Passing**: 100% of enhanced patterns working correctly

## Risks and Mitigations

1. **Risk**: Native JSON doesn't handle regex as expected
   - **Mitigation**: Explicit serialization strategy with testing

2. **Risk**: Performance degradation from serialization
   - **Mitigation**: Benchmark and optimize prepare_for_json

3. **Risk**: Client-side regex compatibility issues
   - **Mitigation**: Comprehensive testing across pattern types

## References

- [Enhanced Patterns Gap Analysis](/ENHANCED-PATTERNS-GAP-ANALYSIS.md)
- [Elixir 1.18 JSON Documentation](https://hexdocs.pm/elixir/1.18/JSON.html)
- [Pattern API Implementation](../RSOLV-api/lib/rsolv_api_web/controllers/api/v1/pattern_controller.ex)