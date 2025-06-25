# AST Test Infrastructure for RFC-031

## Overview

This document describes the test infrastructure for multi-language AST parsing in RSOLV's RFC-031 implementation.

## Test Structure

### Core Test Support

1. **`test/support/ast_test_case.ex`**
   - Shared test case module with common helpers
   - Test code samples for each language and vulnerability type
   - AST node finding and assertion helpers
   - Temporary file management

2. **`test/support/mock_parsers.ex`**
   - Mock AST responses for testing without external dependencies
   - Pre-defined AST structures for known test cases
   - Enables fast unit testing

### Test Files

1. **`test/rsolv_api/ast/port_poc_test.exs`**
   - Basic Port communication tests
   - Python parser integration tests
   - Validates JSON protocol

2. **`test/rsolv_api/ast/multi_language_parsing_test.exs`**
   - Comprehensive multi-language parsing tests
   - Security pattern detection tests
   - Performance and concurrency tests
   - Parser crash recovery tests

### Test Runner

- **`test/run_ast_tests.sh`** - Convenience script to run all AST tests

## Test Categories

### Language Coverage

Each language has tests for:
- Simple parsing (hello world)
- Syntax error handling
- Common vulnerability patterns
- Safe vs vulnerable code comparison

Supported languages:
- ✅ Python (fully tested)
- ✅ JavaScript (fully tested)
- 🏷️ Ruby (tests written, parser pending)
- 🏷️ PHP (tests written, parser pending)
- 🏷️ Java (tests written, parser pending)
- 🏷️ Elixir (tests written, parser pending)

### Security Pattern Tests

For each language, we test detection of:
- SQL Injection (string concatenation vs parameterized)
- Command Injection (direct execution vs safe alternatives)
- XSS (for languages with HTML output)
- Language-specific vulnerabilities

### Performance Tests

- Single file parsing time (<200ms target)
- Concurrent parsing (10 simultaneous requests)
- Average response time under load
- Parser crash recovery time

## Test Data

### Vulnerable Code Examples

Each language includes test cases for:
1. **Vulnerable versions** - Code with security issues
2. **Safe versions** - Properly secured alternatives
3. **Expected findings** - What vulnerabilities should be detected

Example:
```python
# Vulnerable
query = f"SELECT * FROM users WHERE id = {user_id}"

# Safe
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```

### AST Structure Examples

Mock parsers return realistic AST structures:
- Python: Uses CPython AST format
- JavaScript: Uses ESTree/Babel format
- Ruby: Uses Parser gem format
- PHP: Uses PHP-Parser format
- Java: Uses JavaParser format
- Elixir: Uses Elixir AST format

## Running Tests

### All AST Tests
```bash
cd RSOLV-api
./test/run_ast_tests.sh
```

### Specific Test File
```bash
mix test test/rsolv_api/ast/multi_language_parsing_test.exs
```

### With Coverage
```bash
MIX_ENV=test mix coveralls.html
```

## Test Configuration

In `config/test.exs`:
- `use_mock_parsers: true` - Use mocks instead of real parsers
- `parser_timeout: 5_000` - 5 second timeout for tests
- `session_timeout: 300_000` - 5 minute session timeout

## Adding New Tests

1. Add test code samples to `ast_test_case.ex`
2. Add expected vulnerabilities to `expected_vulnerabilities/3`
3. Add mock AST response to `mock_parsers.ex`
4. Write test in `multi_language_parsing_test.exs`

## Integration Points

The test infrastructure validates:
1. **Port Communication** - JSON protocol works correctly
2. **Parser Integration** - Each language parser returns valid AST
3. **Security Detection** - Vulnerabilities are correctly identified
4. **Performance** - Meets <2s for 10 files requirement
5. **Reliability** - Handles errors and crashes gracefully

## Next Steps

1. Implement real parsers for each language
2. Add more vulnerability patterns
3. Test with real vulnerable applications (*Goat repos)
4. Performance optimization based on test results
5. Add integration tests with TypeScript client