# Additional Rails Vulnerability Patterns

This document captures 20 additional Rails-specific vulnerabilities discovered during research that are not currently covered in our Rails patterns. These should be implemented as new patterns to provide comprehensive Rails security coverage.

## Priority Vulnerabilities (Critical/High Severity)

### 1. Rails YAML Deserialization (CVE-2013-0156)
- **Severity**: Critical
- **CWE**: CWE-502 (Deserialization of Untrusted Data)
- **Description**: One of the most critical Rails vulnerabilities allowing RCE through YAML deserialization
- **Vulnerable Patterns**:
  ```ruby
  YAML.load(params[:data])
  YAML.load(cookies[:session])
  YAML.load(request.body.read)
  ```
- **Attack Vector**: Crafted YAML payload can instantiate arbitrary Ruby objects leading to code execution
- **Real CVEs**: CVE-2013-0156, CVE-2013-0269, CVE-2013-0333
- **Recommendation**: Use YAML.safe_load or JSON instead

### 2. Rails Secret Token Exposure
- **Severity**: Critical
- **CWE**: CWE-798 (Use of Hard-coded Credentials)
- **Description**: Exposed secret_key_base allows session forgery and decryption
- **Vulnerable Patterns**:
  ```ruby
  config.secret_key_base = "hardcoded_secret_string"
  SECRET_KEY_BASE = "literal_key_in_code"
  Rails.application.secrets.secret_key_base = "exposed_key"
  ```
- **Attack Vector**: Attacker can forge sessions, decrypt cookies, bypass authentication
- **Recommendation**: Use Rails credentials or environment variables

### 3. Rails Unsafe Send/Public_send
- **Severity**: High
- **CWE**: CWE-470 (Use of Externally-Controlled Input to Select Classes or Code)
- **Description**: Dynamic method invocation allowing calls to dangerous methods
- **Vulnerable Patterns**:
  ```ruby
  object.send(params[:method])
  model.send("#{params[:action]}_all")
  user.public_send(params[:attribute])
  ```
- **Attack Vector**: Call private methods, bypass access control, execute dangerous operations
- **Recommendation**: Whitelist allowed methods, avoid dynamic dispatch with user input

### 4. Rails Open Redirect (Different from Template Redirect)
- **Severity**: High
- **CWE**: CWE-601 (URL Redirection to Untrusted Site)
- **Description**: Unvalidated redirects enabling phishing attacks
- **Vulnerable Patterns**:
  ```ruby
  redirect_to params[:return_to]
  redirect_to request.referer
  redirect_to session[:redirect_url]
  ```
- **Attack Vector**: Phishing, credential theft, malware distribution
- **Recommendation**: Validate redirect URLs, use URL helpers, whitelist domains

### 5. Rails Missing CSRF Meta Tags
- **Severity**: High
- **CWE**: CWE-352 (Cross-Site Request Forgery)
- **Description**: Missing or disabled CSRF protection
- **Vulnerable Patterns**:
  ```ruby
  skip_before_action :verify_authenticity_token
  protect_from_forgery except: [:create, :update]
  # Missing <%= csrf_meta_tags %> in layout
  ```
- **Attack Vector**: CSRF attacks on state-changing operations
- **Recommendation**: Always include CSRF meta tags, avoid skipping verification

### 6. Rails Insecure Direct Object Reference (IDOR)
- **Severity**: High
- **CWE**: CWE-639 (Authorization Bypass Through User-Controlled Key)
- **Description**: No authorization checks on resource access
- **Vulnerable Patterns**:
  ```ruby
  @user = User.find(params[:id])
  @document = Document.find(params[:document_id])
  @order = current_user.company.orders.find(params[:id]) # Still vulnerable if no company check
  ```
- **Attack Vector**: Access other users' data, modify unauthorized resources
- **Recommendation**: Always verify ownership/permissions before resource access

## Medium Severity Vulnerabilities

### 7. Rails Timing Attack on Authentication
- **Severity**: Medium
- **CWE**: CWE-208 (Observable Timing Discrepancy)
- **Description**: String comparison timing leaks allowing token enumeration
- **Vulnerable Patterns**:
  ```ruby
  if user.api_token == params[:token]
  if password == stored_password
  return false unless token == expected_token
  ```
- **Attack Vector**: Statistical analysis to determine valid tokens/passwords
- **Recommendation**: Use ActiveSupport::SecurityUtils.secure_compare

### 8. Rails Unsafe JSON Parsing
- **Severity**: Medium
- **CWE**: CWE-502 (Deserialization of Untrusted Data)
- **Description**: JSON.load can instantiate arbitrary objects
- **Vulnerable Patterns**:
  ```ruby
  JSON.load(params[:json])
  JSON.load(request.body)
  JSON.load(File.read(user_file))
  ```
- **Attack Vector**: Object instantiation, potential code execution
- **Recommendation**: Use JSON.parse instead of JSON.load

### 9. Rails Debug Information Leakage
- **Severity**: Medium
- **CWE**: CWE-215 (Insertion of Sensitive Information Into Debugging Code)
- **Description**: Logging sensitive data in production
- **Vulnerable Patterns**:
  ```ruby
  Rails.logger.info "Password: #{password}"
  logger.debug "API Key: #{api_key}"
  puts "Credit Card: #{card_number}"
  ```
- **Attack Vector**: Log file exposure reveals sensitive data
- **Recommendation**: Filter sensitive parameters, use filter_parameters

### 10. Rails File Upload Without Validation
- **Severity**: Medium
- **CWE**: CWE-434 (Unrestricted Upload of File with Dangerous Type)
- **Description**: Missing file type/size/content validation
- **Vulnerable Patterns**:
  ```ruby
  File.open(Rails.root.join('uploads', params[:file].original_filename), 'wb')
  send_file params[:file].path
  # No content type validation
  ```
- **Attack Vector**: Upload malicious files, XSS via file serving, DoS
- **Recommendation**: Validate file types, scan content, limit sizes

### 11. Rails Unsafe Regex (ReDoS)
- **Severity**: Medium
- **CWE**: CWE-1333 (Inefficient Regular Expression Complexity)
- **Description**: User input in regex causing denial of service
- **Vulnerable Patterns**:
  ```ruby
  Regexp.new(params[:pattern])
  /#{params[:search]}/
  string.match(params[:regex])
  ```
- **Attack Vector**: CPU exhaustion through catastrophic backtracking
- **Recommendation**: Validate/sanitize regex input, use timeouts

### 12. Rails Unsafe Cache Key Generation
- **Severity**: Medium
- **CWE**: CWE-94 (Improper Control of Generation of Code)
- **Description**: User input in cache keys without sanitization
- **Vulnerable Patterns**:
  ```ruby
  Rails.cache.fetch("user_#{params[:id]}")
  cache_key = "search:#{params[:query]}"
  fragment_cache_key = "#{controller_name}/#{params[:filter]}"
  ```
- **Attack Vector**: Cache poisoning, cache key collision
- **Recommendation**: Sanitize cache keys, use digest for user input

### 13. Rails HTTP Header Injection
- **Severity**: Medium
- **CWE**: CWE-113 (Improper Neutralization of CRLF Sequences)
- **Description**: User input in response headers
- **Vulnerable Patterns**:
  ```ruby
  response.headers[params[:header]] = params[:value]
  headers['X-Custom'] = user_input
  response.set_header('Location', params[:url])
  ```
- **Attack Vector**: Response splitting, header injection, cache poisoning
- **Recommendation**: Validate header names/values, avoid user input in headers

## Lower Severity / Best Practice Violations

### 14. Rails Missing Rate Limiting
- **Severity**: Medium
- **CWE**: CWE-307 (Improper Restriction of Excessive Authentication Attempts)
- **Description**: No protection against brute force attacks
- **Vulnerable Patterns**:
  ```ruby
  # No rack-attack or similar
  # No throttling on login attempts
  # No API rate limiting
  ```
- **Attack Vector**: Brute force attacks, API abuse, DoS
- **Recommendation**: Implement rack-attack or similar rate limiting

### 15. Rails Missing Content Security Policy
- **Severity**: Low
- **CWE**: CWE-1021 (Improper Restriction of Rendered UI Layers)
- **Description**: No CSP headers configured
- **Vulnerable Patterns**:
  ```ruby
  # Missing content_security_policy configuration
  # Using unsafe-inline or unsafe-eval
  # Overly permissive CSP
  ```
- **Attack Vector**: XSS attacks more effective without CSP
- **Recommendation**: Configure strict CSP headers

### 16. Rails Missing Secure Headers
- **Severity**: Low
- **CWE**: CWE-693 (Protection Mechanism Failure)
- **Description**: Missing security headers
- **Vulnerable Patterns**:
  ```ruby
  # Missing X-Frame-Options
  # Missing X-Content-Type-Options
  # Missing Strict-Transport-Security
  ```
- **Attack Vector**: Clickjacking, MIME sniffing, protocol downgrade
- **Recommendation**: Use secure_headers gem or configure manually

### 17. Rails Unsafe Database Column Names
- **Severity**: Low
- **CWE**: CWE-89 (SQL Injection)
- **Description**: Dynamic column names from user input
- **Vulnerable Patterns**:
  ```ruby
  User.where(params[:column] => value)
  order(params[:sort_by])
  pluck(params[:fields])
  ```
- **Attack Vector**: Information disclosure, potential SQL injection
- **Recommendation**: Whitelist allowed columns

### 18. Rails Asset Pipeline Information Disclosure
- **Severity**: Low
- **CWE**: CWE-200 (Exposure of Sensitive Information)
- **Description**: Development assets in production
- **Vulnerable Patterns**:
  ```ruby
  # Source maps in production
  # Uncompiled assets served
  # Debug comments in assets
  ```
- **Attack Vector**: Source code disclosure, internal structure exposure
- **Recommendation**: Proper asset compilation for production

### 19. Rails Weak Password Requirements
- **Severity**: Low
- **CWE**: CWE-521 (Weak Password Requirements)
- **Description**: Insufficient password validation
- **Vulnerable Patterns**:
  ```ruby
  validates :password, length: { minimum: 1 }
  # No complexity requirements
  # No password strength checking
  ```
- **Attack Vector**: Weak passwords easily compromised
- **Recommendation**: Implement strong password requirements

### 20. Rails API Token in URL
- **Severity**: Low
- **CWE**: CWE-598 (Use of GET Request Method with Sensitive Query Strings)
- **Description**: Sensitive tokens in GET parameters
- **Vulnerable Patterns**:
  ```ruby
  "api.example.com/users?token=#{api_token}"
  link_to "Download", "/api/download?api_key=#{key}"
  redirect_to "/dashboard?session=#{session_token}"
  ```
- **Attack Vector**: Token leakage via logs, referrer, history
- **Recommendation**: Use headers or POST body for sensitive data

## Implementation Priority

Based on severity and real-world impact, implement in this order:

1. **Phase 1 (Critical)**: YAML deserialization, Secret token exposure
2. **Phase 2 (High Impact)**: Unsafe send, Open redirect, Missing CSRF meta tags, IDOR
3. **Phase 3 (Common Issues)**: Timing attacks, File upload validation, Debug info leakage
4. **Phase 4 (Best Practices)**: Rate limiting, Security headers, Password requirements

## Research Sources
- CVE database entries for Rails
- Rails Security Guide
- OWASP Ruby on Rails Cheat Sheet
- Real-world vulnerability reports
- Brakeman static analyzer rules
- Rails security mailing list archives