# RFC-008 Pattern Categorization Strategy

**Date**: June 7, 2025  
**Purpose**: Define how to categorize 448 existing patterns into tiered API structure  
**Status**: Implemented

## Pattern Distribution Strategy

### Tier 1: Public Patterns (25-30 patterns)
**Purpose**: Trust building, demos, competitive transparency  
**Access**: No authentication required  
**Business Goal**: Show capability without revealing competitive advantages

**Selected Patterns**:

#### Basic OWASP Patterns (20 patterns)
- **SQL Injection**: 2 basic patterns (string concatenation, template literals)
- **XSS**: 3 basic patterns (innerHTML, document.write, eval)
- **Broken Access Control**: 2 patterns (missing authorization, direct object references)
- **Cryptographic Failures**: 2 patterns (MD5, plain text storage)
- **Injection**: 3 patterns (command injection, LDAP injection, NoSQL injection)
- **Security Misconfiguration**: 3 patterns (default passwords, debug enabled, CORS)
- **Vulnerable Components**: 2 patterns (known CVE usage, outdated dependencies)
- **Authentication Failures**: 3 patterns (weak passwords, session fixation, brute force)

#### Trust Building Patterns (8 patterns)
- **Log4Shell Detection**: Show we can detect major CVEs
- **React Basic Security**: dangerouslySetInnerHTML usage
- **Node.js Path Traversal**: Basic directory traversal
- **Express Security Headers**: Missing security headers
- **JWT Basic Issues**: Algorithm confusion, weak secrets
- **CSRF Basic Protection**: Missing CSRF tokens
- **Input Validation**: Basic regex injection
- **File Upload**: Basic unrestricted file upload

### Tier 2: Protected Patterns (200+ patterns)
**Purpose**: Advanced framework-specific detection for paying customers  
**Access**: Valid RSOLV API key required  
**Business Goal**: Justify premium pricing with advanced capabilities

**Categories**:

#### Advanced Framework Patterns (150 patterns)
- **Rails Advanced**: 15+ patterns (mass assignment, unsafe reflection, etc.)
- **Django Advanced**: 15+ patterns (ORM injection, template injection, etc.)
- **React Advanced**: 20+ patterns (state injection, prop injection, etc.)
- **Node.js Advanced**: 25+ patterns (prototype pollution, async injection, etc.)
- **Express Advanced**: 15+ patterns (middleware bypass, route pollution, etc.)
- **PHP Advanced**: 20+ patterns (deserialization, include injection, etc.)
- **Java Advanced**: 40+ patterns (deserialization, reflection, etc.)

#### CVE-Specific Patterns (30 patterns)
- **Spring4Shell**: Complete detection pattern
- **Log4Shell**: Advanced variations and bypasses
- **Struts2 RCE**: Multiple CVE variants
- **Jackson Deserialization**: CVE-2017-7525 and variants
- **ImageMagick**: ImageTragick vulnerabilities
- **Apache Tomcat**: Various CVEs

#### Advanced Cryptography (20 patterns)
- **Padding Oracle**: Advanced detection
- **Timing Attack**: Side channel vulnerabilities
- **Weak Random**: PRNG predictability
- **Certificate Validation**: Advanced bypass techniques

### Tier 3: AI-Specific Patterns (30+ patterns)
**Purpose**: Unique AI vulnerability detection - core competitive advantage  
**Access**: API key + AI feature flag  
**Business Goal**: Command premium pricing for "first AI security platform"

**AI-Specific Vulnerability Categories**:

#### AI Hallucination Patterns (10 patterns)
- **Hallucinated Dependencies**: npm/pip packages that don't exist
- **Hallucinated APIs**: Methods/functions that don't exist
- **Hallucinated Security Functions**: crypto functions with wrong parameters
- **Hallucinated Libraries**: Entire libraries suggested by AI
- **Version Hallucination**: Package versions that never existed

#### Context Confusion Patterns (8 patterns)
- **Authentication Mix**: Secure and insecure auth patterns mixed
- **Permission Confusion**: Authorization logic contradictions
- **Protocol Confusion**: HTTP/HTTPS mixed incorrectly
- **Framework Confusion**: Rails patterns in Django code, etc.
- **Environment Confusion**: Dev patterns in prod code

#### AI Copy-Paste Anti-Patterns (7 patterns)
- **Repeated Vulnerabilities**: Same vulnerability across multiple files
- **Template Injection Chains**: AI copying vulnerable templates
- **Configuration Propagation**: Insecure configs repeated
- **Comment-Code Mismatch**: Comments describing security, code vulnerable

#### Weak AI Cryptography (5 patterns)
- **AI-Suggested DES/3DES**: AI recommending deprecated encryption
- **AI-Suggested MD5/SHA1**: AI recommending weak hashing
- **AI-Suggested RC4**: AI recommending weak stream cipher
- **Hardcoded Crypto Keys**: AI generating weak example keys
- **Weak Random Seeds**: AI using predictable randomness

### Tier 4: Enterprise Patterns (Future)
**Purpose**: Customer-specific patterns and rules  
**Access**: Enterprise authentication  
**Business Goal**: Create switching costs and lock-in

**Planned Categories**:
- Customer-specific vulnerability patterns
- Organization-specific compliance rules
- Custom security policies
- Industry-specific regulations (HIPAA, PCI-DSS, SOX)

## Implementation Migration Plan

### Phase 1: Extract and Categorize (Day 1)
1. **Analyze Current Patterns**: Review all 448 patterns in detail
2. **Create Category Mapping**: Map each pattern to appropriate tier
3. **Validate Selection**: Ensure public patterns are trust-building
4. **Document Decisions**: Record rationale for each categorization

### Phase 2: Database Schema (Day 2)
```sql
CREATE TABLE pattern_tiers (
  id UUID PRIMARY KEY,
  name VARCHAR(50) NOT NULL, -- 'public', 'protected', 'ai', 'enterprise'
  description TEXT,
  requires_auth BOOLEAN DEFAULT false,
  requires_feature_flag VARCHAR(50), -- 'ai_patterns' for AI tier
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE security_patterns (
  id UUID PRIMARY KEY,
  pattern_id VARCHAR(100) NOT NULL UNIQUE, -- e.g. 'sql-injection-basic'
  tier_id UUID REFERENCES pattern_tiers(id),
  language VARCHAR(50) NOT NULL,
  pattern_regex TEXT NOT NULL,
  severity VARCHAR(20) NOT NULL,
  message TEXT NOT NULL,
  fix_pattern TEXT,
  owasp_category VARCHAR(10), -- A01, A02, etc.
  cve_references TEXT[], -- Array of CVE IDs
  framework_specific VARCHAR(50), -- 'rails', 'django', etc.
  validation_function VARCHAR(100), -- For AI patterns needing external validation
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);
```

### Phase 3: API Implementation (Day 2-3)
```elixir
# RSOLV-api endpoint structure
defmodule RsolvWeb.PatternController do
  # Public patterns - no auth
  def public_patterns(conn, %{"language" => language}) do
    patterns = SecurityPatterns.get_by_tier_and_language("public", language)
    json(conn, %{tier: "public", patterns: patterns})
  end
  
  # Protected patterns - API key required
  def protected_patterns(conn, %{"language" => language}) do
    with {:ok, customer} <- authenticate_api_key(conn) do
      patterns = SecurityPatterns.get_by_tier_and_language("protected", language)
      json(conn, %{tier: "protected", patterns: patterns})
    end
  end
  
  # AI patterns - API key + feature flag
  def ai_patterns(conn, %{"language" => language}) do
    with {:ok, customer} <- authenticate_api_key(conn),
         true <- FeatureFlags.enabled?(:ai_patterns, customer) do
      patterns = SecurityPatterns.get_by_tier_and_language("ai", language)
      json(conn, %{tier: "ai", patterns: patterns})
    end
  end
end
```

## Marketing Message Validation

### Public Patterns Enable
- ✅ "Try our security scanner free" 
- ✅ "See how RSOLV detects vulnerabilities"
- ✅ "Basic OWASP Top 10 coverage included"

### Protected Patterns Enable
- ✅ "448 comprehensive security patterns"
- ✅ "Advanced framework-specific detection"
- ✅ "CVE detection including Log4Shell"
- ✅ "10x more patterns than generic tools"

### AI Patterns Enable
- ✅ "First AI vulnerability detection platform"
- ✅ "Detects AI hallucination vulnerabilities" 
- ✅ "Only platform for AI-generated code security"
- ✅ "Zero competition in AI security space"

## Security Considerations

### Pattern Protection
- All pattern regex and logic moves to protected tiers
- Public patterns are basic enough to show capability without revealing IP
- AI patterns remain completely proprietary
- Git history will be sanitized to remove all pattern content

### Access Control
- API key validation for protected and AI tiers
- Feature flag system for gradual AI pattern rollout
- Rate limiting to prevent pattern harvesting
- Audit logging for pattern access

### Competitive Protection  
- Public patterns: Industry standard, no competitive advantage lost
- Protected patterns: Advanced but not unique methodology
- AI patterns: Complete competitive moat, zero exposure

This categorization enables our "first AI security platform" marketing while protecting core IP and creating clear value tiers for customers.