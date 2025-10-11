# ADR-030: Worker Thread Isolation for Untrusted Regex Patterns

**Status**: Implemented
**Date**: 2025-10-11
**Impact**: High - Prevents infinite hangs from pattern API regex
**Related**: ADR-008 (Pattern Serving API), ADR-014 (Elixir AST Service), RFC-060 (Phase 4.2)

## Context

During RFC-060 Phase 4.2 Ruby/RailsGoat testing, the security scanner experienced a catastrophic failure: **infinite hang on `app/models/user.rb` after 19+ minutes of blocking execution**. Investigation revealed that a Ruby regex pattern from the Pattern API caused catastrophic backtracking, blocking the JavaScript event loop indefinitely.

### The Problem

JavaScript's regex engine has no built-in timeout mechanism. When a poorly-constructed regex pattern encounters specific input, it can enter catastrophic backtracking:

```ruby
# This simple 9-line file caused infinite hang:
class Performance < ApplicationRecord
  belongs_to :user

  def reviewer_name
   u = User.find_by_id(self.reviewer)
   u.full_name if u.respond_to?("fullname")
  end
end
```

**Key Challenge**: Promise.race timeout **cannot interrupt synchronous operations**. The regex execution blocks the event loop, preventing any timeout mechanism from firing.

### Trust Model

**Pattern API serves untrusted content**:
- Patterns come from external API (ADR-008)
- Pattern authors may not test all edge cases
- Malicious or poorly-tested patterns could DoS the scanner
- Cannot validate all patterns are safe before execution

**Production Impact**:
- GitHub Actions workflows canceled after 19+ minutes
- RailsGoat scan: 146 files → only 11 scanned before hang
- Complete workflow failure, no vulnerabilities reported

## Decision

**Implement SafeDetector: Worker Thread-based pattern execution with forceful termination capability**.

Execute **ALL** regex patterns in isolated worker threads with 30-second timeout and `worker.terminate()` for forceful interruption.

### Architecture

```typescript
// src/security/safe-detector.ts
export class SafeDetector implements ISecurityDetector {
  private activeWorkers = new Set<Worker>();
  private defaultTimeout = 30000; // 30 seconds

  async detect(code: string, language: string, filePath?: string): Promise<Vulnerability[]> {
    const patterns = await this.patternSource.getPatternsByLanguage(language);
    return this.runPatternsInWorker(code, language, patterns, filePath, this.defaultTimeout);
  }

  private async runPatternsInWorker(...): Promise<Vulnerability[]> {
    const worker = new Worker(workerPath, {
      workerData: { code, language, patterns, filePath }
    });
    this.activeWorkers.add(worker);

    return new Promise((resolve) => {
      // Timeout with FORCEFUL termination
      const timeoutId = setTimeout(() => {
        logger.warn(`Pattern execution timeout for ${filePath}`);
        worker.terminate(); // Actually works - kills blocking thread!
        this.activeWorkers.delete(worker);
        resolve([]);
      }, timeout);

      worker.on('message', (msg) => {
        clearTimeout(timeoutId);
        this.activeWorkers.delete(worker);
        resolve(msg.data);
        worker.terminate();
      });

      worker.on('error', (error) => {
        clearTimeout(timeoutId);
        this.activeWorkers.delete(worker);
        logger.error(`Worker error for ${filePath}:`, error);
        resolve([]);
      });
    });
  }

  cleanup(): void {
    // Force terminate all active workers
    this.activeWorkers.forEach(worker => worker.terminate());
    this.activeWorkers.clear();
  }
}
```

### Worker Thread Implementation

```javascript
// src/security/detector-worker.js (CommonJS for worker compatibility)
const { parentPort, workerData } = require('worker_threads');

// Execute patterns in isolated thread
const vulnerabilities = [];
for (const pattern of workerData.patterns) {
  if (pattern.patterns.regex) {
    for (const regex of pattern.patterns.regex) {
      let match;
      while ((match = regex.exec(workerData.code)) !== null) {
        // Pattern matching happens in isolated thread
        // Can be terminated via worker.terminate()
        vulnerabilities.push({/* ... */});
      }
    }
  }
}

parentPort.postMessage({ data: vulnerabilities });
```

## Alternatives Considered

### 1. Child Processes ❌
**Pros**: Complete OS-level isolation
**Cons**: Too heavyweight (~100ms startup), slower than workers (~5-10ms)

### 2. VM Module Sandboxing ❌
**Pros**: Lighter weight than workers
**Cons**: **Cannot interrupt infinite loops** - same problem as Promise.race

### 3. safe-regex2 Pre-validation ⚠️
**Pros**: No execution overhead, catches ~80% of issues
**Cons**: Detection only, doesn't prevent hangs, false negatives exist
**Decision**: Use as **complementary** validation, not primary defense

### 4. Pattern Modification (Fix Individual Patterns) ❌
**Pros**: Targeted, no performance overhead
**Cons**: Reactive (not comprehensive), new patterns could still cause hangs

### 5. Worker Threads (CHOSEN) ✅
**Pros**:
- **Forceful termination via worker.terminate() actually works**
- Clean isolation from main thread
- ~5-10ms overhead acceptable
- Protects against ALL future problematic patterns

**Cons**:
- Slight performance overhead per file
- More complex debugging (errors in workers)
- Deployment complexity (worker file must be in dist)

## Consequences

### ✅ Positive

1. **Eliminates Infinite Hangs**
   - RailsGoat: 19+ minutes (hung) → 23.6 seconds ✅
   - user.rb: Infinite hang → ~70ms ✅
   - 146/146 files scanned successfully

2. **Future-Proof Protection**
   - Protects against any future problematic patterns
   - No need to validate individual patterns before deployment
   - Pattern API team can be more aggressive with pattern development

3. **Maintains Backward Compatibility**
   - Same ISecurityDetector interface
   - Drop-in replacement for SecurityDetectorV2
   - No changes required in calling code

4. **Graceful Degradation**
   - Timeout → returns empty array (no vulnerabilities)
   - Logs warning with file path for debugging
   - Scan continues with remaining files

### ⚠️ Negative

1. **Performance Overhead**
   - Worker creation: ~5-10ms per file
   - For 146-file repo: ~1.5 seconds total overhead
   - **Acceptable tradeoff** vs 19-minute hang

2. **Deployment Complexity**
   - Must include `detector-worker.js` in dist/ directory
   - Build script modification required:
     ```json
     "build": "bun build src/index.ts --outdir dist --minify && cp src/security/detector-worker.js dist/"
     ```

3. **Debugging Complexity**
   - Worker errors are reported differently
   - Cannot set breakpoints in worker threads (easily)
   - Stack traces show worker origin

4. **Resource Usage**
   - Each worker thread consumes memory
   - Multiple concurrent scans could create many workers
   - **Mitigation**: Single worker per file, cleanup after completion

## Implementation Details

### Files Created
- `src/security/safe-detector.ts` (257 lines) - Main detector class
- `src/security/detector-worker.js` (99 lines) - Worker thread execution
- `src/security/safe-detector.test.ts` (209 lines) - Comprehensive test suite (11 tests)

### Integration Points
- `src/scanner/repository-scanner.ts` - Uses SafeDetector instead of SecurityDetectorV2
- `dist/detector-worker.js` - Deployed worker file
- Build process - Copies worker to dist

### Test Coverage
```typescript
describe('SafeDetector', () => {
  test('detects vulnerabilities in Ruby code');
  test('handles timeout gracefully (returns empty array)');
  test('terminates worker after timeout');
  test('cleans up workers on completion');
  test('handles worker errors gracefully');
  test('maintains ISecurityDetector interface compatibility');
  // ... 11 tests total
});
```

## Validation

### Before SafeDetector
| Metric | Result |
|--------|--------|
| RailsGoat Scan Time | 19+ min (hung, canceled) |
| Files Scanned | 11/146 (hung on file 11) |
| user.rb Processing | Infinite hang (blocking) |
| Vendor Files Skipped | 0 (separate bug) |
| Workflow Result | ❌ Failure (timeout) |

### After SafeDetector
| Metric | Result |
|--------|--------|
| RailsGoat Scan Time | **23.6 seconds** ✅ |
| Files Scanned | **146/146** ✅ |
| user.rb Processing | **~70ms** ✅ |
| Vendor Files Skipped | 11 (fixed in same PR) |
| Workflow Result | **✅ Success (35 vulnerabilities)** |

### Performance Impact
- **50x speedup**: 19 minutes → 24 seconds
- **Overhead**: ~5-10ms per file (acceptable)
- **Reliability**: 100% scan completion rate

## Related Documentation

- **Discovery**: RFC-060 Phase 4.2 Subtask #1b (Ruby/RailsGoat verification)
- **Pattern API**: ADR-008 Pattern Serving API for IP Protection
- **Similar Architecture**: ADR-014 Elixir-Powered AST Analysis Service (isolation pattern)
- **Debugging Guide**: `docs/troubleshooting/regex-hang-debugging.md`
- **Implementation**: `docs/rfcs/RFC-060-phase-4-implementation.md`

## Future Considerations

1. **Worker Pool Implementation**
   - Current: 1 worker per file (serial)
   - Future: Pool of N workers (parallel)
   - **Benefit**: Faster scans for large repositories
   - **Tradeoff**: More memory, more complexity

2. **Pattern Reporting**
   - Report problematic patterns to Pattern API team
   - Include timeout metrics
   - Enable pattern optimization

3. **Dynamic Timeout Adjustment**
   - Smaller files: 10 second timeout
   - Larger files: 30+ second timeout
   - Based on file size heuristics

4. **safe-regex2 Integration**
   - Pre-validate patterns before execution
   - Warn Pattern API team of potentially unsafe patterns
   - Catch issues before production deployment

## References

- **GitHub Actions Workflow**: RailsGoat scan runs 18421691756, 18422064557 (success)
- **Test Repository**: https://github.com/RSOLV-dev/railsgoat
- **Implementation PR**: vk/d5bf-rfc-060-phase-4 (merged 2025-10-11)
- **Commit**: 15a67ed7662a132cf1e51b7785dcc866b1dcce21

## Lessons Learned

1. **Synchronous operations cannot be interrupted by async timeouts**
   - Promise.race is ineffective against blocking loops
   - Worker threads are the only viable solution

2. **Trust boundary enforcement requires architectural change**
   - Cannot trust external regex patterns
   - Isolation must be enforced at system level, not application level

3. **Performance tradeoffs are acceptable for reliability**
   - 5-10ms overhead per file is negligible
   - 19-minute hang → 24-second scan is 50x improvement

4. **Conservative approach preferred for security infrastructure**
   - Run ALL patterns in workers, not just "suspected" patterns
   - Better safe than sorry when dealing with untrusted input

## Decision Outcome

**Status**: ✅ Implemented and verified in production (2025-10-11)

The SafeDetector architecture successfully:
- Eliminates infinite hangs from regex patterns
- Maintains backward compatibility
- Provides graceful degradation
- Enables future pattern expansion without risk

This decision establishes the precedent: **All untrusted code execution must be isolated in worker threads or separate processes**.
