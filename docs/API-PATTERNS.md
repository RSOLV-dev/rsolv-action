# Pattern API Documentation

**Version**: 2.0  
**Base URL**: `https://api.rsolv.dev`  
**Authentication**: API Key (Bearer token)

## Overview

The RSOLV Pattern API provides access to a comprehensive library of security vulnerability detection patterns. Patterns are organized into tiers based on sensitivity and access requirements.

## Pattern Tiers

| Tier | Access Level | Pattern Count | Use Case |
|------|-------------|---------------|----------|
| **Public** | No authentication | 27 patterns | Basic patterns, demos, open source |
| **Business** | API key required | 389 patterns | Production security scanning |
| **Enterprise** | Enterprise API key | 32 patterns | Advanced patterns, customer-specific vulnerabilities |

**Total Production Patterns**: 448 verified security patterns across 8 languages and 6 frameworks

## Supported Languages

- **JavaScript/TypeScript** (123 patterns) - Node.js, React, Vue, Angular
- **Python** (89 patterns) - Core Python vulnerabilities  
- **Ruby** (72 patterns) - Core Ruby vulnerabilities
- **Java** (64 patterns) - Spring, Jakarta EE, Android
- **Elixir/Phoenix** (22 patterns) - OTP, GenServer, Ecto
- **Django** (18 patterns) - Django-specific framework patterns
- **Rails** (18 patterns) - Rails-specific framework patterns
- **PHP** (25 patterns) - Laravel, WordPress, Symfony
- **CVE Patterns** (42 patterns) - Cross-language vulnerability patterns

**Total**: 448 patterns across 8 languages and 6 frameworks

### Framework-Specific Coverage
- **Django**: Python web framework security patterns
- **Rails**: Ruby on Rails framework security patterns  
- **Phoenix**: Elixir web framework security patterns
- **Laravel**: PHP framework patterns (included in PHP)
- **Spring**: Java framework patterns (included in Java)
- **Express.js**: Node.js framework patterns (included in JavaScript)

## Authentication

### API Key Authentication
```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  https://api.rsolv.dev/api/v1/patterns/business/javascript
```

### Public Endpoints (No Auth)
```bash
curl https://api.rsolv.dev/api/v1/patterns/public/javascript
```

## Endpoints

### 1. Public Patterns

#### `GET /api/v1/patterns/public/:language`

Get public security patterns for a specific language.

**Parameters:**
- `language` (path) - Programming language (e.g., javascript, python, ruby)

**Response:**
```json
{
  "patterns": [
    {
      "id": "js-basic-sql-injection",
      "name": "Basic SQL Injection",
      "description": "Detects string concatenation in SQL queries",
      "type": "sql_injection",
      "severity": "high",
      "languages": ["javascript", "typescript"],
      "regex": "[\\\\'\\\"\\`].*?(SELECT|INSERT|UPDATE|DELETE).*?[\\\\'\\\"\\`]\\\\s*\\\\+",
      "cwe_id": "CWE-89",
      "owasp_category": "A03:2021",
      "recommendation": "Use parameterized queries or prepared statements",
      "test_cases": {
        "vulnerable": [
          "const query = \\\"SELECT * FROM users WHERE id = \\\" + userId;"
        ],
        "safe": [
          "const query = \\\"SELECT * FROM users WHERE id = ?\\\"; db.execute(query, [userId]);"
        ]
      }
    }
  ],
  "total": 3,
  "tier": "public"
}
```

### 2. Business Patterns

#### `GET /api/v1/patterns/business/:language`

Get business-tier security patterns for production security scanning.

**Authentication:** Required (API Key)

**Parameters:**
- `language` (path) - Programming language

**Response:**
```json
{
  "patterns": [...],
  "total": 389,
  "tier": "business"
}
```

### 3. Enterprise Patterns

#### `GET /api/v1/patterns/enterprise/:language`

Get enterprise-tier security patterns for advanced vulnerability detection.

**Authentication:** Required (Enterprise API Key)

**Parameters:**
- `language` (path) - Programming language

**Response:**
```json
{
  "patterns": [...],
  "total": 32,
  "tier": "enterprise"
}
```

### 4. Cross-Language Patterns

#### `GET /api/v1/patterns/cve`

Get CVE-based patterns that apply across multiple languages.

**Authentication:** Required for full access

**Response:**
```json
{
  "patterns": [
    {
      "id": "log4shell-detection",
      "name": "Log4Shell Vulnerability (CVE-2021-44228)",
      "description": "Detects Log4j JNDI lookup injection",
      "type": "remote_code_execution",
      "severity": "critical",
      "languages": ["java", "kotlin", "scala"],
      "regex": "\\\\$\\\\{jndi:(ldap|rmi|dns)://",
      "cve_id": "CVE-2021-44228",
      "cvss_score": 10.0
    }
  ],
  "total": 42,
  "tier": "business"
}
```

### 5. Pattern Types

#### `GET /api/v1/patterns/type/:vulnerability_type`

Get patterns by vulnerability type across all languages.

**Parameters:**
- `vulnerability_type` (path) - Type of vulnerability (sql_injection, xss, etc.)

**Vulnerability Types:**
- `sql_injection`
- `xss`
- `command_injection`
- `path_traversal`
- `hardcoded_secret`
- `insecure_crypto`
- `csrf`
- `xxe`
- `ssrf`
- `deserialization`

### 6. Health Check

#### `GET /api/v1/patterns/health`

Check API health and pattern statistics.

**Response:**
```json
{
  "status": "healthy",
  "patterns": {
    "total": 448,
    "by_tier": {
      "public": 27,
      "business": 389,
      "enterprise": 32
    },
    "by_language": {
      "javascript": 123,
      "python": 89,
      "ruby": 72,
      "java": 64,
      "elixir": 22,
      "django": 18,
      "rails": 18,
      "php": 25,
      "cve": 42
    }
  },
  "cache_status": "warm",
  "last_updated": "2025-06-10T22:30:00Z"
}
```

## Pattern Schema

### Pattern Object
```json
{
  "id": "string",                    // Unique pattern identifier
  "name": "string",                  // Human-readable name
  "description": "string",           // Detailed description
  "type": "vulnerability_type",      // Type of vulnerability
  "severity": "critical|high|medium|low",
  "languages": ["string"],           // Applicable languages
  "frameworks": ["string"],          // Specific frameworks (optional)
  "regex": "string",                 // Detection regex pattern
  "default_tier": "tier_name",       // Access tier
  "cwe_id": "CWE-XXX",              // CWE identifier
  "cve_id": "CVE-YYYY-XXXX",        // CVE identifier (if applicable)
  "owasp_category": "string",        // OWASP Top 10 category
  "cvss_score": 0.0,                // CVSS score (if applicable)
  "recommendation": "string",        // Fix recommendation
  "test_cases": {
    "vulnerable": ["string"],        // Example vulnerable code
    "safe": ["string"]              // Example safe code
  }
}
```

## Rate Limits

- **Public tier**: 1000 requests/hour
- **Business tier**: 10000 requests/hour  
- **Enterprise tier**: Unlimited

### Rate Limiting by Tier

| Tier | Hourly Limit | Daily Limit | Use Case |
|------|-------------|-------------|----------|
| Public | 1,000 | 10,000 | Demo and evaluation |
| Business | 10,000 | 100,000 | Production security scanning |
| Enterprise | Unlimited | Unlimited | High-volume scanning |

## Error Responses

### 401 Unauthorized
```json
{
  "error": "unauthorized",
  "message": "Valid API key required"
}
```

### 403 Forbidden
```json
{
  "error": "forbidden",
  "message": "Insufficient permissions for enterprise patterns"
}
```

### 404 Not Found
```json
{
  "error": "not_found",
  "message": "Language 'cobol' not supported"
}
```

### 429 Rate Limited
```json
{
  "error": "rate_limited",
  "message": "Rate limit exceeded",
  "retry_after": 3600
}
```

## Usage Examples

### Basic Security Scan
```bash
# Get public JavaScript patterns
curl https://api.rsolv.dev/api/v1/patterns/public/javascript

# Get all CVE patterns
curl -H "Authorization: Bearer sk-your-api-key" \
  https://api.rsolv.dev/api/v1/patterns/cve
```

### Language-Specific Analysis
```bash
# Python security patterns
curl -H "Authorization: Bearer sk-your-api-key" \
  https://api.rsolv.dev/api/v1/patterns/business/python

# Ruby on Rails patterns
curl -H "Authorization: Bearer sk-your-api-key" \
  https://api.rsolv.dev/api/v1/patterns/business/ruby
```

### Advanced Enterprise Detection
```bash
# Enterprise-tier JavaScript patterns
curl -H "Authorization: Bearer sk-enterprise-api-key" \
  https://api.rsolv.dev/api/v1/patterns/enterprise/javascript
```

## Integration Examples

### JavaScript/Node.js
```javascript
const axios = require('axios');

class RSOLVPatternClient {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.baseURL = 'https://api.rsolv.dev/api/v1/patterns';
  }

  async getPatterns(language, tier = 'business') {
    const headers = tier !== 'public' ? {
      'Authorization': `Bearer ${this.apiKey}`
    } : {};

    const response = await axios.get(
      `${this.baseURL}/${tier}/${language}`,
      { headers }
    );
    
    return response.data.patterns;
  }
}

// Usage
const client = new RSOLVPatternClient('sk-your-api-key');
const jsPatterns = await client.getPatterns('javascript');
```

### Python
```python
import requests

class RSOLVPatternClient:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = 'https://api.rsolv.dev/api/v1/patterns'

    def get_patterns(self, language, tier='business'):
        headers = {}
        if tier != 'public':
            headers['Authorization'] = f'Bearer {self.api_key}'
            
        response = requests.get(
            f'{self.base_url}/{tier}/{language}',
            headers=headers
        )
        response.raise_for_status()
        return response.json()['patterns']

# Usage
client = RSOLVPatternClient('sk-your-api-key')
python_patterns = client.get_patterns('python')
```

### cURL Scripts
```bash
#!/bin/bash
# Complete security audit script

API_KEY="sk-your-api-key"
BASE_URL="https://api.rsolv.dev/api/v1/patterns"

echo "Fetching security patterns..."

# Get patterns for multiple languages
for lang in javascript python ruby java; do
    echo "Getting $lang patterns..."
    curl -s -H "Authorization: Bearer $API_KEY" \
      "$BASE_URL/business/$lang" \
      -o "${lang}_patterns.json"
done

# Get CVE patterns
echo "Getting CVE patterns..."
curl -s -H "Authorization: Bearer $API_KEY" \
  "$BASE_URL/cve" \
  -o "cve_patterns.json"

echo "Pattern collection complete!"
```

## Caching

- **Pattern data**: Cached for 1 hour
- **Health checks**: Cached for 5 minutes
- **Rate limit counters**: Sliding window (1 hour)

## Support

For API support and feature requests:
- Email: api-support@rsolv.dev
- Documentation: https://docs.rsolv.dev
- Status page: https://status.rsolv.dev

## Tier Limitations and Access Levels

### Public Tier Limitations
- **Access**: No authentication required
- **Pattern Count**: 27 patterns (6% of total library)
- **Languages**: All supported languages but limited patterns per language
- **Use Cases**: Demos, proof-of-concept, open source projects
- **Rate Limits**: 1,000 requests/hour, 10,000 requests/day
- **Support**: Community support only
- **Commercial Use**: Permitted with attribution

**Public Tier Pattern Distribution:**
- JavaScript: 3 basic patterns
- Python: 3 basic patterns  
- Ruby: 3 basic patterns
- Java: 3 basic patterns
- Elixir: 3 basic patterns
- PHP: 3 basic patterns
- Django: 3 basic patterns
- Rails: 3 basic patterns
- CVE: 3 essential patterns

### Business Tier Limitations
- **Access**: API key authentication required
- **Pattern Count**: 389 patterns (87% of total library)
- **Languages**: Complete coverage for production security scanning
- **Use Cases**: Production applications, security audits, CI/CD integration
- **Rate Limits**: 10,000 requests/hour, 100,000 requests/day
- **Support**: Email support with 24-hour response SLA
- **Commercial Use**: Full commercial license included

**Business Tier Capabilities:**
- Complete OWASP Top 10 coverage
- Framework-specific vulnerability detection
- Industry-standard security patterns
- Production-ready accuracy and performance
- Regular pattern updates and maintenance

### Enterprise Tier Limitations
- **Access**: Enterprise API key with enhanced authentication
- **Pattern Count**: 32 patterns (7% of total library, highest value)
- **Languages**: Advanced patterns across all supported languages
- **Use Cases**: Large enterprises, security vendors, advanced threat detection
- **Rate Limits**: Unlimited requests
- **Support**: Dedicated support with 4-hour response SLA
- **Commercial Use**: Unlimited commercial usage rights

**Enterprise Tier Exclusives:**
- Advanced zero-day vulnerability patterns
- Customer-specific vulnerability signatures
- Early access to new pattern releases
- Custom pattern development services
- Priority API response times
- Dedicated infrastructure resources

### Pattern Quality Standards

**All Tiers:**
- Patterns tested against real-world codebases
- False positive rate below 5%
- Regular updates for new vulnerability research
- Clear remediation guidance for each pattern
- CWE and OWASP mapping for compliance

**Business and Enterprise Only:**
- Advanced context analysis
- Framework-specific optimization
- Supply chain vulnerability detection
- Custom severity scoring
- Integration with security platforms

### API Key Management

**Business Tier Keys:**
- Format: `sk-business-[32-char-identifier]`
- Renewable every 90 days
- Tied to specific domains/IP ranges
- Usage analytics and monitoring included

**Enterprise Tier Keys:**
- Format: `sk-enterprise-[32-char-identifier]`
- Renewable annually with auto-renewal option
- Advanced security features (IP whitelisting, rate limiting bypass)
- Detailed usage analytics and custom reporting
- Multiple keys per organization supported

### Compliance and Certifications

**Business Tier:**
- SOC 2 Type II compliant
- GDPR compliant data handling
- Industry-standard encryption (TLS 1.3)
- Regular security audits

**Enterprise Tier:**
- All Business Tier compliance plus:
- ISO 27001 certification  
- PCI DSS compliance for payment processing environments
- HIPAA compliance for healthcare applications
- Custom compliance requirements supported

## Changelog

### v2.0 (June 2025)
- **3-Tier Architecture**: Implemented public, business, and enterprise tiers
- **448 Production Patterns**: Verified and deployed comprehensive pattern library
- **8 Language Support**: JavaScript, Python, Ruby, Java, Elixir, PHP, Django, Rails
- **CVE Pattern Integration**: 42 cross-language vulnerability patterns
- **Enhanced Rate Limiting**: Tier-specific rate limits and access controls
- **Production Infrastructure**: Full BEAM clustering and horizontal scalability

### v1.0 (May 2025)
- Initial Pattern API release
- Basic pattern serving functionality
- Foundation for security pattern management