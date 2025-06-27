# RSOLV AST Service Security Architecture

## Overview

The RSOLV AST Service implements defense-in-depth security architecture to safely analyze untrusted code while protecting customer data and system integrity. This document describes the security controls, threat model, and operational procedures.

## Table of Contents

1. [Security Principles](#security-principles)
2. [Threat Model](#threat-model)
3. [Security Controls](#security-controls)
4. [Encryption Architecture](#encryption-architecture)
5. [Session Management](#session-management)
6. [Sandboxing Architecture](#sandboxing-architecture)
7. [Audit Logging](#audit-logging)
8. [Code Retention Policy](#code-retention-policy)
9. [Parser Security](#parser-security)
10. [Operational Security](#operational-security)
11. [Incident Response](#incident-response)
12. [Compliance](#compliance)

## Security Principles

1. **Zero Trust**: Never trust user-provided code
2. **Defense in Depth**: Multiple layers of security controls
3. **Least Privilege**: Minimal permissions for all components
4. **Data Minimization**: Don't retain customer code after analysis
5. **Audit Everything**: Comprehensive logging for compliance and forensics

## Threat Model

### Assets to Protect
- Customer source code confidentiality
- System availability and integrity
- Security pattern intellectual property
- Parser infrastructure

### Threat Actors
- Malicious code submissions (DoS attempts)
- Data exfiltration attempts
- Parser exploitation attempts
- Timing-based attacks
- Resource exhaustion attacks

### Attack Vectors
1. **Code Injection**: Malicious code designed to exploit parsers
2. **Resource Exhaustion**: Large files, infinite loops, memory bombs
3. **Information Disclosure**: Attempts to extract system information
4. **Denial of Service**: Overwhelming the system with requests
5. **Data Exfiltration**: Attempts to steal other customers' data

## Security Controls

### 1. Input Validation
- Maximum file size: 10MB
- Supported languages only (JavaScript, Python, Ruby, Java, Go, PHP)
- UTF-8 encoding validation
- Malicious pattern detection (eval, shell injection, etc.)

### 2. Rate Limiting
- Per-customer session limits
- Per-language parser limits (100 req/min)
- Concurrent request throttling
- Backpressure handling

### 3. Authentication & Authorization
- Customer ID verification
- Session-based access control
- Encrypted session tokens
- Automatic session expiration

## Encryption Architecture

### Algorithm: AES-256-GCM
- 256-bit keys for maximum security
- Authenticated encryption preventing tampering
- Unique IV for each encryption operation
- AEAD (Authenticated Encryption with Associated Data)

### Key Management
```elixir
# Key Generation
key = :crypto.strong_rand_bytes(32)  # 256 bits

# Encryption
{ciphertext, iv, auth_tag} = Encryption.encrypt(plaintext, key)

# Decryption
{:ok, plaintext} = Encryption.decrypt(ciphertext, key, iv, auth_tag)
```

### Key Rotation
- Automatic rotation based on age (default: 24 hours)
- Manual rotation supported
- Version tracking for all keys
- Multi-version decryption support
- Atomic rotation with concurrency protection

```elixir
# Rotation Configuration
SessionManager.create_session(customer_id, ttl, %{
  key_rotation_interval: :timer.hours(12)  # Rotate every 12 hours
})

# Manual Rotation
{:ok, new_key} = Encryption.rotate_key(session_id, current_key)
```

### Key Storage
- Keys stored in protected ETS tables
- Never persisted to disk
- Cleared on session expiration
- Secure memory handling

## Session Management

### Session Creation
```elixir
{:ok, session} = SessionManager.create_session(customer_id, ttl_seconds)
```

### Session Properties
- Unique session ID (cryptographically random)
- Customer isolation
- TTL-based expiration (default: 1 hour)
- Maximum 10 sessions per customer
- Automatic cleanup of expired sessions

### Session Security
- Sessions bound to customer ID
- Cannot access other customers' sessions
- Automatic expiration enforcement
- Secure session token generation

## Sandboxing Architecture

### BEAM-Native Process Isolation
Instead of Docker containers, we leverage BEAM's built-in process isolation:

```elixir
# Resource Limits
- Memory: 128MB per parser
- CPU: 1M reductions
- Timeout: 15 seconds
- Priority: Low

# Process Spawning
{:ok, port} = Port.open({:spawn_executable, parser_path}, [
  :binary,
  :exit_status,
  {:line, 1_000_000},
  {:args, parser_args},
  {:cd, sandbox_dir},
  {:env, filtered_env}
])
```

### Security Features
1. **Process Isolation**: Each parser runs in isolated OS process
2. **Resource Limits**: Memory, CPU, and time constraints
3. **No Network Access**: Parsers cannot make network requests
4. **No File System Access**: Restricted to sandbox directory
5. **Environment Filtering**: Sensitive env vars removed

### Monitoring
- Real-time memory usage tracking
- CPU reduction monitoring
- Automatic process termination on limits
- Health check intervals

## Audit Logging

### Event Types
```elixir
# Security Events
- :parser_spawned
- :parser_crashed
- :parser_resource_limit
- :malicious_input_detected
- :session_created/:session_expired
- :encryption_key_rotated
- :code_scrubbed
```

### Log Structure
```elixir
%{
  timestamp: DateTime.utc_now(),
  event_type: :atom,
  severity: :info | :warning | :error | :critical,
  correlation_id: "uuid",
  customer_id: integer(),
  metadata: %{...}
}
```

### Retention & Analysis
- Buffered in-memory storage
- Periodic flush to persistent storage
- Query API for investigation
- Prometheus metrics export
- No customer code in logs

## Code Retention Policy

### Zero Retention Guarantee
Customer code is **never** retained after analysis:

1. **Immediate Scrubbing**: Code cleared from memory after analysis
2. **Error Path Coverage**: Code scrubbed even on failures
3. **Process Cleanup**: Force garbage collection
4. **ETS Exclusions**: Only temporary AST cache allowed

### Verification
```elixir
# After analysis
CodeRetention.verify_no_code_in_memory(code)
CodeRetention.verify_no_code_in_ets(code)
CodeRetention.verify_no_code_in_processes(code)
```

### Compliance Report
```elixir
{:ok, report} = CodeRetention.generate_retention_report()
# Returns verification status for audit
```

## Parser Security

### Input Validation
```elixir
# Size Limits
max_size = 10 * 1024 * 1024  # 10MB

# Pattern Detection
@malicious_patterns [
  ~r/\$\(.*\)/,           # Shell injection
  ~r/`.*`/,               # Command substitution  
  ~r/\beval\s*\(/,        # Eval usage
  ~r/\.\.[\\/\\]/,         # Path traversal
  ~r/\/etc\//,            # System file access
]

# Complexity Scoring
complexity = calculate_complexity(input)
reject if complexity > threshold
```

### Parser Pool Management
- Pre-warmed parser processes
- Health monitoring
- Automatic recovery from crashes
- Isolation between languages
- Resource usage tracking

### Timeout Enforcement
```elixir
# Strict timeouts
receive do
  {port, {:data, data}} -> process_data(data)
after
  @timeout -> kill_parser_process(port)
end
```

## Operational Security

### Deployment Security
1. **Environment Variables**: Sensitive config via env vars
2. **Secrets Management**: No hardcoded credentials
3. **TLS Only**: All communications encrypted
4. **Network Isolation**: Parsers have no network access

### Monitoring & Alerting
1. **Security Metrics**:
   - Failed authentication attempts
   - Resource limit violations
   - Malicious input detections
   - Parser crashes

2. **Performance Metrics**:
   - Parse times
   - Memory usage
   - Queue depths
   - Cache hit rates

### Access Control
1. **API Authentication**: Required for all endpoints
2. **Rate Limiting**: Per-customer limits
3. **IP Allowlisting**: Optional restriction
4. **Audit Trail**: All access logged

## Incident Response

### Detection
1. **Automated Alerts**:
   - Resource exhaustion
   - Repeated parser crashes
   - Malicious pattern detection
   - Authentication failures

2. **Manual Investigation**:
   - Audit log analysis
   - Correlation ID tracking
   - Customer activity patterns

### Response Procedures
1. **Immediate Actions**:
   - Isolate affected parser
   - Block malicious customer
   - Preserve evidence

2. **Investigation**:
   - Analyze audit logs
   - Review code submissions
   - Check for lateral movement

3. **Recovery**:
   - Restart affected services
   - Rotate encryption keys
   - Update security patterns

### Communication
1. Incident notification procedures
2. Customer communication templates
3. Regulatory reporting requirements

## Compliance

### GDPR Compliance
- No personal data in code analysis
- Right to deletion (code not retained)
- Data processing audit trail
- Privacy by design

### SOC2 Requirements
- Access control documentation
- Audit logging
- Incident response procedures
- Security training records

### Security Standards
- OWASP Secure Coding Practices
- CWE/SANS Top 25 coverage
- NIST Cybersecurity Framework alignment

## Configuration Reference

### Environment Variables
```bash
# Security Settings
ENCRYPTION_KEY_ROTATION_HOURS=24
SESSION_TTL_SECONDS=3600
MAX_SESSIONS_PER_CUSTOMER=10
MAX_FILE_SIZE_MB=10

# Parser Limits
PARSER_MEMORY_LIMIT_MB=128
PARSER_TIMEOUT_SECONDS=15
PARSER_CPU_REDUCTIONS=1000000

# Rate Limiting
RATE_LIMIT_PER_MINUTE=100
CONCURRENT_REQUEST_LIMIT=10
```

### Security Headers
```elixir
# Required Headers
"X-Customer-ID": "12345"
"X-Session-ID": "abc123..."
"Content-Type": "application/json"
```

## Security Checklist

### Pre-Deployment
- [ ] All tests passing
- [ ] Security scan completed
- [ ] Encryption keys rotated
- [ ] Rate limits configured
- [ ] Audit logging enabled

### Operational
- [ ] Monitor security alerts
- [ ] Review audit logs daily
- [ ] Update security patterns
- [ ] Rotate credentials quarterly
- [ ] Security training current

### Incident Response
- [ ] Incident response plan tested
- [ ] Contact list updated
- [ ] Backup procedures verified
- [ ] Recovery time objectives met

## Conclusion

The RSOLV AST Service implements comprehensive security controls appropriate for analyzing untrusted code. The defense-in-depth approach ensures that even if one control fails, others maintain security. Regular security reviews and updates ensure continued protection against evolving threats.