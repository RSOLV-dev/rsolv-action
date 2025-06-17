# Pattern Migration Methodology

## Overview

This document describes our Test-Driven Development (TDD) approach to migrating security patterns from language-based files to individual pattern modules with comprehensive vulnerability metadata.

## Migration Status

**Current Progress**: 169 out of 169 patterns migrated (100.0%)
**Updated**: January 10, 2025

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

PHP Patterns (25/25 completed ✅) - **Added 5 new patterns during migration**:
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
- `php-hardcoded-credentials` ✓✓ (Hardcoded Credentials) - AST included in pattern file - **NEW**
- `php-insecure-random` ✓✓ (Insecure Random Number Generation) - AST included in pattern file - **NEW**
- `php-nosql-injection` ✓✓ (NoSQL Injection) - AST included in pattern file - **NEW**
- `php-weak-password-hash` ✓✓ (Weak Password Hashing) - AST included in pattern file - **NEW**
- `php-file-inclusion` ✓✓ (File Inclusion Vulnerability) - AST included in pattern file - **NEW**

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
- 149/149 patterns have AST rules (100%)
- 149/149 AST enhancements included in pattern files (100%)
- 0 AST enhancements in central file

**AST Migration Progress**: ✅ COMPLETE - All migrated patterns include AST enhancements in their individual pattern files

## Summary

### ✅ **Completed Languages** (100% migrated):
- **JavaScript**: 30/30 patterns ✅
- **Python**: 12/12 patterns ✅
- **PHP**: 25/25 patterns ✅ (includes 5 patterns added during migration)
- **Ruby**: 20/20 patterns ✅
- **Java**: 17/17 patterns ✅
- **Elixir**: 28/28 patterns ✅
- **Total**: 132/132 language patterns complete

### ✅ **Framework Patterns COMPLETE**:
- **Rails**: 18/18 patterns migrated ✅ (100%)
- **Django**: 19/19 patterns migrated ✅ (100%)

### 📊 **Overall Progress**:
- **Total Patterns**: 169
- **Migrated**: 169 (100.0%) ✅ **COMPLETE**
- **Remaining**: 0

### 🎯 **Planned Additions**:
- **Laravel (PHP framework)**: Research and implement Laravel-specific vulnerability patterns

Elixir Patterns (28/28 COMPLETE ✅):
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
- `elixir-weak-crypto-sha1` ✓✓ (Weak Cryptography - SHA1) - AST included in pattern file
- `elixir-missing-csrf-protection` ✓✓ (Missing CSRF Protection in Phoenix forms) - AST included in pattern file
- `elixir-debug-mode-enabled` ✓✓ (Debug Mode Enabled with Information Disclosure) - AST included in pattern file
- `elixir-unsafe-process-spawn` ✓✓ (Unsafe Process Spawning without Supervision) - AST included in pattern file
- `elixir-atom-exhaustion` ✓✓ (Atom Table Exhaustion Risk) - AST included in pattern file
- `elixir-ets-public-table` ✓✓ (Public ETS Table Security Risk) - AST included in pattern file
- `elixir-missing-auth-pipeline` ✓✓ (Missing Authentication Pipeline in Phoenix Controllers) - AST included in pattern file
- `elixir-unsafe-redirect` ✓✓ (Open Redirect Vulnerability in Phoenix) - AST included in pattern file
- `elixir-hardcoded-secrets` ✓✓ (Hardcoded Secrets and Credentials) - AST included in pattern file
- `elixir-unsafe-json-decode` ✓✓ (Unsafe JSON Decoding leading to DoS) - AST included in pattern file
- `elixir-cookie-security` ✓✓ (Insecure Cookie Flags in Phoenix) - AST included in pattern file
- `elixir-unsafe-file-upload` ✓✓ (Unsafe File Upload Handling) - AST included in pattern file
- `elixir-insufficient-input-validation` ✓✓ (Insufficient Input Validation in Ecto) - AST included in pattern file
- `elixir-exposed-error-details` ✓✓ (Information Disclosure via Error Messages) - AST included in pattern file
- `elixir-unsafe-genserver-calls` ✓✓ (Unsafe GenServer Calls enabling RCE) - AST included in pattern file
- `elixir-missing-ssl-verification` ✓✓ (Missing SSL Certificate Verification) - AST included in pattern file
- `elixir-weak-password-hashing` ✓✓ (Weak Password Hashing) - AST included in pattern file

Rails Patterns (18/18 COMPLETE ✅):
- `rails-missing-strong-parameters` ✓✓ (Missing Strong Parameters) - AST included in pattern file
- `rails-dangerous-attr-accessible` ✓✓ (Dangerous attr_accessible Usage) - AST included in pattern file
- `rails-activerecord-injection` ✓✓ (ActiveRecord SQL Injection) - AST included in pattern file
- `rails-dynamic-finder-injection` ✓✓ (Dynamic Finder Injection) - AST included in pattern file
- `rails-erb-injection` ✓✓ (ERB Template Injection) - AST included in pattern file
- `rails-template-xss` ✓✓ (Rails Template XSS) - AST included in pattern file
- `rails-unsafe-route-constraints` ✓✓ (Unsafe Route Constraints) - AST included in pattern file
- `rails-unsafe-globbing` ✓✓ (Unsafe Route Globbing) - AST included in pattern file
- `rails-insecure-session-config` ✓✓ (Insecure Session Configuration) - AST included in pattern file
- `rails-dangerous-production-config` ✓✓ (Dangerous Production Configuration) - AST included in pattern file - **Contains CVE-2020-8264**
- `rails-insecure-cors` ✓✓ (Insecure CORS Configuration) - AST included in pattern file
- `rails-actionmailer-injection` ✓✓ (ActionMailer Injection) - AST included in pattern file
- `rails-session-fixation` ✓✓ (Session Fixation) - AST included in pattern file
- `rails-insecure-session-data` ✓✓ (Insecure Session Data Storage) - AST included in pattern file
- `rails-cve-2022-22577` ✓✓ (CVE-2022-22577 - XSS in Action Pack) - AST included in pattern file
- `rails-cve-2021-22881` ✓✓ (CVE-2021-22881 - Host Authorization Open Redirect) - AST included in pattern file
- `rails-callback-security-bypass` ✓✓ (Rails Callback Security Bypass) - AST included in pattern file
- `rails-cve-2019-5418` ✓✓ (CVE-2019-5418 - File Content Disclosure) - AST included in pattern file

Django Patterns (19/19 COMPLETE ✅):
- `django-orm-injection` ✓✓ (Django ORM SQL Injection) - AST included in pattern file
- `django-nosql-injection` ✓✓ (Django NoSQL Injection) - AST included in pattern file
- `django-template-xss` ✓✓ (Django Template XSS) - AST included in pattern file
- `django-template-injection` ✓✓ (Django Template Injection) - AST included in pattern file
- `django-debug-settings` ✓✓ (Django Debug Settings) - AST included in pattern file
- `django-insecure-session` ✓✓ (Django Insecure Session Configuration) - AST included in pattern file
- `django-missing-security-middleware` ✓✓ (Django Missing Security Middleware) - AST included in pattern file
- `django-broken-auth` ✓✓ (Django Broken Authentication) - AST included in pattern file
- `django-authorization-bypass` ✓✓ (Django Authorization Bypass) - AST included in pattern file
- `django-csrf-bypass` ✓✓ (Django CSRF Bypass) - AST included in pattern file
- `django-clickjacking` ✓✓ (Django Clickjacking Vulnerability) - AST included in pattern file
- `django-model-injection` ✓✓ (Django Model Injection) - AST included in pattern file
- `django-mass-assignment` ✓✓ (Django Mass Assignment) - AST included in pattern file
- `django-unsafe-url-patterns` ✓✓ (Django Unsafe URL Patterns) - AST included in pattern file
- `django-cve-2021-33203` ✓✓ (Django CVE-2021-33203 - Potential Directory Traversal) - AST included in pattern file
- `django-cve-2021-33571` ✓✓ (Django CVE-2021-33571 - IPv4 Validation Bypass) - AST included in pattern file
- `django-cve-2020-13254` ✓✓ (Django CVE-2020-13254 - Cache Key Injection) - AST included in pattern file
- `django-cve-2019-14234` ✓✓ (Django CVE-2019-14234 - SQL Injection in JSONField) - AST included in pattern file
- `django-cve-2018-14574` ✓✓ (Django CVE-2018-14574 - Open Redirect) - AST included in pattern file

**🎉 MIGRATION COMPLETE**: All 169 patterns successfully migrated to individual modules with TDD methodology and comprehensive AST enhancements!

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
        type: :cve,
        id: "CVE-XXXX-XXXXX",
        title: "Official CVE title",
        url: "https://cve.mitre.org/..."
      },
      %{
        type: :cwe,
        id: "CWE-XXX",
        title: "CWE category name",
        url: "https://cwe.mitre.org/..."
      }
    ],
    attack_vectors: [
      "Specific attack method 1",
      "Specific attack method 2"
    ],
    real_world_impact: [
      "Business impact 1",
      "Technical impact 2"
    ],
    cve_examples: [
      %{
        id: "CVE-XXXX-XXXXX",
        description: "What happened",
        severity: "critical|high|medium|low",
        cvss: 9.8,
        note: "Additional context"
      }
    ],
    detection_notes: "How this pattern works and what it catches",
    safe_alternatives: [
      "Safe approach 1",
      "Safe approach 2"
    ],
    additional_context: %{
      common_mistakes: [...],
      secure_patterns: [...],
      framework_specific_notes: [...]
    }
  }
end
```

### 5. Pattern Module Structure

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
  
  @impl true
  def vulnerability_metadata do
    # Comprehensive metadata as shown above
  end
  
  @impl true
  def ast_enhancement do
    # AST rules to reduce false positives
  end
end
```

### 6. AST Enhancement Requirements

**MANDATORY**: Every migrated pattern must include AST enhancement rules to reduce false positives.

**NEW APPROACH**: AST enhancement is now implemented directly in each pattern module via the `ast_enhancement/0` function, not in a centralized file.

See pattern files for examples of AST enhancement implementation.

---

## Migration Summary (Updated June 15, 2025)

### ✅ **Completed Languages** (100% migrated):
- **JavaScript**: 30/30 patterns ✅
- **Python**: 12/12 patterns ✅
- **PHP**: 25/25 patterns ✅ (includes 5 patterns added during migration)
- **Ruby**: 20/20 patterns ✅
- **Java**: 17/17 patterns ✅
- **Elixir**: 28/28 patterns ✅
- **Total**: 132/132 language patterns complete

### ✅ **Framework Patterns COMPLETE**:
- **Rails**: 18/18 patterns migrated ✅ (100%)
- **Django**: 19/19 patterns migrated ✅ (100%)

### 📊 **Overall Progress**:
- **Total Patterns**: 169 (increased from original 157 due to patterns added during migration)
- **Migrated**: 169 (100.0%) ✅ **COMPLETE**
- **Remaining**: 0
- **AST Enhancements**: 169/169 migrated patterns have AST rules (100%)

### 🎯 **Planned Additions**:
- **Laravel (PHP framework)**: Research and implement Laravel-specific vulnerability patterns including:
  - Eloquent ORM injection
  - Blade template XSS
  - Mass assignment vulnerabilities
  - CSRF bypass patterns
  - File upload vulnerabilities
  - Session fixation
  - Insecure JWT handling
  - Command injection via artisan
  - Insecure API authentication
  - Middleware bypass patterns

### 📁 **File Locations**:
- **Pattern files**: `/home/dylan/dev/rsolv/RSOLV-api/lib/rsolv_api/security/patterns/`
- **Test files**: `/home/dylan/dev/rsolv/RSOLV-api/test/rsolv_api/security/patterns/`
- **Language modules**: `/home/dylan/dev/rsolv/RSOLV-api/lib/rsolv_api/security/patterns/[language].ex`

### 🔑 **Key Achievements**:
- All migrated patterns follow strict TDD methodology
- Comprehensive vulnerability metadata with CVE references
- AST enhancements embedded in each pattern module
- Consistent pattern structure across all languages
- Added real-world attack vectors and remediation guidance
- Framework-specific patterns properly categorized