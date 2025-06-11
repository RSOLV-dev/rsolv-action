# Pattern API Documentation

**Version**: 2.0  
**Base URL**: `https://api.rsolv.dev`  
**Authentication**: API Key (Bearer token)

## Overview

The RSOLV Pattern API provides access to a comprehensive library of security vulnerability detection patterns. Patterns are organized into tiers based on sensitivity and access requirements.

## Pattern Tiers

| Tier | Access Level | Pattern Count | Use Case |
|------|-------------|---------------|----------|
| **Public** | No authentication | ~25 | Basic patterns, demos, open source |
| **Protected** | API key required | ~120 | Production security scanning |
| **AI** | API key + feature flag | ~20 | AI-powered vulnerability detection |
| **Enterprise** | Enterprise auth | ~5 | Customer-specific patterns |

## Supported Languages

- **Elixir/Phoenix** (28 patterns)
- **JavaScript/TypeScript** (27 patterns)
- **PHP** (25 patterns)
- **Ruby** (20 patterns)
- **Django/Python** (19 patterns)
- **Rails** (18 patterns)
- **Java** (17 patterns)
- **Python** (12 patterns)
- **CVE Patterns** (4 patterns)

**Total**: 170 patterns across 9 categories

## Authentication

### API Key Authentication
```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  https://api.rsolv.dev/api/v1/patterns/protected/javascript
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

### 2. Protected Patterns

#### `GET /api/v1/patterns/protected/:language`

Get protected security patterns for a specific language.

**Authentication:** Required (API Key)

**Parameters:**
- `language` (path) - Programming language

**Response:**
```json
{
  "patterns": [...],
  "total": 89,
  "tier": "protected"
}
```

### 3. AI Patterns

#### `GET /api/v1/patterns/ai/:language`

Get AI-enhanced security patterns for advanced vulnerability detection.

**Authentication:** Required (API Key + AI feature flag)

**Parameters:**
- `language` (path) - Programming language

**Response:**
```json
{
  "patterns": [...],
  "total": 15,
  "tier": "ai"
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
  "tier": "protected"
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
      "protected": 389,
      "ai": 32
    },
    "by_language": {
      "javascript": 123,
      "python": 89,
      "ruby": 72,
      "java": 64
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
- **Protected tier**: 10000 requests/hour  
- **AI tier**: 5000 requests/hour
- **Enterprise tier**: Unlimited

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
  "message": "Insufficient permissions for AI patterns"
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
  https://api.rsolv.dev/api/v1/patterns/protected/python

# Ruby on Rails patterns
curl -H "Authorization: Bearer sk-your-api-key" \
  https://api.rsolv.dev/api/v1/patterns/protected/ruby
```

### Advanced AI Detection
```bash
# AI-enhanced JavaScript patterns
curl -H "Authorization: Bearer sk-your-api-key" \
  https://api.rsolv.dev/api/v1/patterns/ai/javascript
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

  async getPatterns(language, tier = 'protected') {
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

    def get_patterns(self, language, tier='protected'):
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
      "$BASE_URL/protected/$lang" \
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

## Changelog

### v2.0 (June 2025)
- Added AI pattern tier
- Introduced CVE-specific patterns
- Enhanced error handling
- Added pattern test cases

### v1.0 (May 2025)
- Initial Pattern API release
- Public and protected tiers
- Support for 8 languages
- 448 total patterns