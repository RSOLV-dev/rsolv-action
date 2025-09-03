# RFC-019: Additional Rails Security Patterns

**RFC ID**: RFC-019  
**Title**: Additional Rails Security Patterns  
**Author**: Security Team  
**Status**: Draft  
**Created**: 2025-01-16  
**Updated**: 2025-01-16  

## Abstract

This RFC proposes adding 20 additional Rails-specific security patterns to enhance our vulnerability detection coverage. These patterns were identified through comprehensive research of Rails CVEs, security advisories, and real-world vulnerability reports. Implementation would increase our Rails pattern coverage from 20 to 40 patterns, making RSOLV the most comprehensive Rails security scanner available.

## Motivation

Our current Rails patterns cover common vulnerabilities but miss several critical security issues:

1. **Critical gaps**: YAML deserialization (CVE-2013-0156), one of the most severe Rails vulnerabilities
2. **Modern threats**: API token exposure, timing attacks, IDOR vulnerabilities
3. **Framework-specific**: Rails-unique vulnerabilities not covered by generic Ruby patterns
4. **Compliance requirements**: Security headers, CSP, rate limiting becoming audit requirements
5. **Market differentiation**: Comprehensive Rails coverage sets us apart from competitors

## Detailed Design

### Pattern Categories

#### 1. Critical Severity (Immediate Implementation)
- **rails-yaml-deserialization**: Detects `YAML.load` with user input (CVE-2013-0156)
- **rails-secret-token-exposure**: Hardcoded `secret_key_base` in code

#### 2. High Severity (Phase 1)
- **rails-unsafe-send**: Dynamic method invocation via `send(params[:method])`
- **rails-open-redirect-controller**: Unvalidated `redirect_to params[:url]`
- **rails-missing-csrf-meta-tags**: Missing CSRF protection or meta tags
- **rails-idor**: Insecure Direct Object Reference without authorization

#### 3. Medium Severity (Phase 2)
- **rails-timing-attack**: String comparison timing vulnerabilities
- **rails-unsafe-json-parsing**: `JSON.load` instead of `JSON.parse`
- **rails-debug-info-leakage**: Sensitive data in logs
- **rails-file-upload-validation**: Unrestricted file uploads
- **rails-unsafe-regex**: ReDoS via user-controlled regex
- **rails-unsafe-cache-keys**: Cache poisoning vulnerabilities
- **rails-http-header-injection**: CRLF injection in headers

#### 4. Best Practices (Phase 3)
- **rails-missing-rate-limiting**: No brute force protection
- **rails-missing-csp**: Missing Content Security Policy
- **rails-missing-secure-headers**: Missing security headers
- **rails-unsafe-column-names**: Dynamic column names from input
- **rails-asset-pipeline-disclosure**: Source maps in production
- **rails-weak-passwords**: Insufficient password requirements
- **rails-api-token-in-url**: Sensitive tokens in GET parameters

### Implementation Example

```ruby
defmodule RsolvApi.Security.Patterns.Rails.YamlDeserialization do
  @moduledoc """
  YAML Deserialization vulnerability pattern for Rails applications.
  
  This pattern detects the extremely dangerous practice of using YAML.load
  with user-controlled input, which can lead to remote code execution.
  
  ## Vulnerability Details
  
  CVE-2013-0156 demonstrated that YAML.load can instantiate arbitrary Ruby
  objects, leading to RCE. This remains one of the most critical Rails vulns.
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  
  @impl true
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "rails-yaml-deserialization",
      name: "YAML Deserialization Vulnerability",
      description: "YAML.load with user input enables remote code execution",
      type: :deserialization,
      severity: :critical,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        ~r/YAML\.load\s*\(\s*params/,
        ~r/YAML\.load\s*\(\s*request\./,
        ~r/YAML\.load\s*\(\s*cookies/,
        ~r/Psych\.load\s*\(\s*params/
      ],
      cwe_id: "CWE-502",
      owasp_category: "A08:2021",
      cve_examples: ["CVE-2013-0156", "CVE-2013-0269", "CVE-2013-0333"]
    }
  end
end
```

### Pattern Distribution by Severity

| Severity | Count | Examples |
|----------|-------|----------|
| Critical | 2 | YAML deserialization, Secret token |
| High | 4 | Unsafe send, Open redirect, CSRF, IDOR |
| Medium | 7 | Timing attacks, File upload, ReDoS |
| Low | 7 | Rate limiting, Security headers |

## Benefits

1. **Security Coverage**: 100% increase in Rails pattern coverage (20 → 40)
2. **Critical Vulnerability Detection**: Catches severe RCE vulnerabilities
3. **Modern Threat Coverage**: Addresses contemporary attack vectors
4. **Compliance Support**: Helps meet security audit requirements
5. **Market Leadership**: Most comprehensive Rails scanner available

## Risks and Mitigation

### Risks
1. **Implementation Time**: ~40 hours for all 20 patterns
2. **False Positives**: Some patterns may need careful tuning
3. **Maintenance**: More patterns to maintain and update

### Mitigation
1. **Phased Rollout**: Implement by severity (Critical → High → Medium → Low)
2. **AST Enhancement**: Each pattern includes false positive reduction
3. **Automated Testing**: Comprehensive test coverage for maintenance

## Implementation Plan

### Phase 1: Critical & High (Week 1)
- [ ] YAML deserialization pattern
- [ ] Secret token exposure pattern
- [ ] Unsafe send pattern
- [ ] Open redirect pattern
- [ ] Missing CSRF pattern
- [ ] IDOR pattern

### Phase 2: Medium Severity (Week 2)
- [ ] Timing attack pattern
- [ ] JSON parsing pattern
- [ ] Debug leakage pattern
- [ ] File upload pattern
- [ ] ReDoS pattern
- [ ] Cache key pattern
- [ ] Header injection pattern

### Phase 3: Best Practices (Week 3)
- [ ] Rate limiting pattern
- [ ] CSP pattern
- [ ] Security headers pattern
- [ ] Column names pattern
- [ ] Asset disclosure pattern
- [ ] Password requirements pattern
- [ ] API token URL pattern

## Success Metrics

1. **Pattern Coverage**: 40 Rails patterns implemented
2. **Test Coverage**: 100% test coverage for new patterns
3. **False Positive Rate**: < 5% on real Rails codebases
4. **Detection Rate**: Catches 100% of known CVE test cases
5. **Performance**: < 10ms average pattern matching time

## Alternatives Considered

1. **Minimal Addition**: Only add critical patterns (2-3 patterns)
   - Pros: Quick implementation
   - Cons: Misses important vulnerabilities

2. **Generic Patterns**: Rely on language-agnostic patterns
   - Pros: Less maintenance
   - Cons: Misses Rails-specific vulnerabilities

3. **Third-party Integration**: Integrate Brakeman rules
   - Pros: Leverage existing work
   - Cons: Licensing, maintenance, less control

## References

- [Rails Security Guide](https://guides.rubyonrails.org/security.html)
- [CVE-2013-0156 Analysis](https://www.rapid7.com/blog/post/2013/01/09/serialization-mischief-in-ruby-land-cve-2013-0156/)
- [OWASP Rails Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html)
- [Brakeman Warning Types](https://brakemanscanner.org/docs/warning_types/)
- Research document: `/RAILS-ADDITIONAL-VULNERABILITIES.md`

## Decision

**Status**: Awaiting approval

**Recommendation**: Approve Phase 1 (Critical & High severity) immediately, with Phases 2-3 following based on customer demand and resource availability.

## Appendix: Pattern Priority Matrix

| Pattern | Severity | Real-world Impact | Implementation Effort | Priority |
|---------|----------|-------------------|----------------------|----------|
| YAML Deserialization | Critical | RCE | Low | P0 |
| Secret Token | Critical | Full Compromise | Low | P0 |
| Unsafe Send | High | Privilege Escalation | Medium | P1 |
| Open Redirect | High | Phishing | Low | P1 |
| Missing CSRF | High | State Change | Low | P1 |
| IDOR | High | Data Breach | Medium | P1 |
| Timing Attack | Medium | Token Bypass | Medium | P2 |
| ... | ... | ... | ... | ... |