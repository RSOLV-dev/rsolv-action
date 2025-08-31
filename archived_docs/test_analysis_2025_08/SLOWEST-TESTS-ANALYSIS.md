# Slowest Tests Analysis

## Top 30 Slowest Tests in AST and Security Modules

Based on test execution timing analysis, here are the slowest tests that may benefit from optimization:

### Critical Performance Tests (> 5 seconds)
1. **11002.6ms** - `stream processing processes file stream without loading all into memory`
2. **7436.4ms** - `performance optimization manages memory efficiently under load`

### Slow Tests (2-3 seconds)
3. **2502.0ms** - `TTL expiration resets TTL on access`
4. **2412.7ms** - `stream processing handles backpressure in stream processing`
5. **2323.8ms** - `resource usage prevention prevents zombie processes from accumulating`
6. **2282.0ms** - `performance optimization scales linearly with CPU cores`
7. **2000.6ms** - `TTL expiration expires entries after TTL`
8. **2000.5ms** - `resource limits enforces CPU timeout on long-running operations`

### Moderate Tests (500ms - 2s)
9. **1142.3ms** - `performance analyzes files within performance budget`
10. **1100.9ms** - `session retrieval removes expired sessions`
11. **1100.4ms** - `session cleanup counts active sessions`
12. **1100.4ms** - `session cleanup automatically cleans up expired sessions`
13. **809.8ms** - `process cleanup kills CPU-intensive processes when port is terminated`
14. **807.8ms** - `process cleanup handles process that ignores SIGTERM`
15. **807.7ms** - `dynamic scaling scales down when low demand`
16. **613.3ms** - `process cleanup cleans up processes on supervisor shutdown`
17. **539.2ms** - `zero code retention verification batch analysis doesn't retain any code`
18. **502.8ms** - `pool initialization starts with configured pool size`

### Parser Pool Tests (300-400ms)
19. **402.8ms** - `dynamic scaling scales up when high demand`
20. **401.9ms** - `parser checkout/checkin handles parser crashes gracefully`
21. **356.6ms** - `batch analysis analyzes multiple files in parallel`
22. **354.0ms** - `pool metrics tracks utilization metrics`
23. **304.9ms** - `port lifecycle management enforces maximum restart attempts`
24. **303.8ms** - `pool metrics tracks parser health`
25. **301.9ms** - `parser checkout/checkin checkin returns parser to pool`
26. **301.9ms** - `parser checkout/checkin blocks when all parsers busy`
27. **301.8ms** - `parser checkout/checkin checkout returns available parser`

### Other Notable Tests
28. **258.2ms** - `end-to-end batch processing handles mixed success and failure gracefully`
29. **256.6ms** - `health monitoring restarts unhealthy ports`
30. **246.5ms** - `end-to-end batch processing processes files from parse to analysis`

## Recommendations

1. **Stream Processing Tests (11s, 2.4s)**: These tests are intentionally slow as they test streaming and backpressure handling. Consider marking with `@tag :slow` to exclude from regular test runs.

2. **Performance Tests (7.4s, 2.3s, 2.0s)**: These test actual performance characteristics and need to run for extended periods. Should be tagged `@tag :performance`.

3. **TTL/Session Tests (2.5s, 2.0s, 1.1s)**: These tests wait for timeouts to occur. Consider:
   - Using shorter TTLs in test environment
   - Mocking time progression
   - Tagging as `@tag :integration`

4. **Parser Pool Tests (300-500ms)**: These are already optimized with the warmup fixes. The time is mostly parser initialization which is necessary.

5. **Process Cleanup Tests (600-800ms)**: These test process termination and cleanup, which inherently takes time. Consider `@tag :integration`.

## Test Suite Optimization Strategy

1. Tag slow tests appropriately:
   ```elixir
   @tag :slow
   @tag :performance 
   @tag :integration
   ```

2. Run different test suites for different purposes:
   - `mix test` - Quick tests only
   - `mix test --include slow` - Include slow tests
   - `mix test --include performance` - Include performance tests
   - `mix test --include integration` - Full integration suite

3. Consider parallel test execution for independent test modules.

4. Mock external dependencies where possible to reduce test execution time.