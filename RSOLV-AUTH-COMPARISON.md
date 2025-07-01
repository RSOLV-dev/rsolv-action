# RSOLV Authentication Architecture vs Phoenix Standards

## Executive Summary

RSOLV uses a **pure API key authentication** model, which differs significantly from Phoenix's `phx.gen.auth` approach. This is intentional and appropriate for RSOLV's use case as an API-only service focused on developer integrations.

## RSOLV's Current Authentication Model

### 1. API Key Authentication
- **Location**: `Authorization: Bearer <api_key>` header
- **Validation**: Direct lookup in `RSOLV.Accounts.get_customer_by_api_key/1`
- **Storage**: Environment variables and in-memory lookup (no database in current implementation)
- **No sessions**: Stateless authentication on every request

### 2. Encryption Key for E2EE (AST Service Only)
- **Location**: `X-Encryption-Key` header (base64 encoded)
- **Purpose**: Client-provided AES-256 key for end-to-end encryption
- **Validation**: Must be exactly 32 bytes (256 bits)
- **Usage**: Only for AST analysis service, not for authentication

## Phoenix phx.gen.auth Standard Pattern

### Traditional Web App Authentication
```elixir
# phx.gen.auth generates:
- User registration/login forms
- Session-based authentication
- CSRF tokens
- Remember me tokens
- Password reset flows
- Email confirmation
- Session cookies
- Phoenix.Token for secure token generation
```

### Typical Flow:
1. User logs in with email/password
2. Server creates session and sets cookie
3. Subsequent requests include session cookie
4. Server validates session on each request

## Key Differences

### 1. Authentication Model
| Aspect | RSOLV | phx.gen.auth |
|--------|-------|--------------|
| Type | API Key | Session-based |
| Storage | Stateless | Stateful (sessions) |
| Transport | Authorization header | Cookies |
| CSRF Protection | Not needed (no cookies) | Required |
| Remember Me | N/A | Token-based |

### 2. Use Case Alignment
- **RSOLV**: API-only service for CI/CD integrations
- **phx.gen.auth**: Web applications with browser users

### 3. Security Model
- **RSOLV**: 
  - API keys are long-lived secrets
  - Rate limiting per customer
  - No browser-specific vulnerabilities (XSS, CSRF)
  
- **phx.gen.auth**:
  - Short-lived sessions
  - CSRF tokens
  - Secure cookie settings

## Is RSOLV Following Best Practices?

### ✅ Yes, for API Services

1. **Stateless Authentication**: Perfect for horizontally scalable APIs
2. **Bearer Token Pattern**: Industry standard for APIs (GitHub, Stripe, etc.)
3. **No Cookie Complexity**: Avoids browser security issues
4. **Simple Integration**: Easy for developers to implement

### 🔍 Areas Following Phoenix/Elixir Best Practices

1. **Plug Architecture**: Uses standard Phoenix controller patterns
2. **Error Handling**: Proper HTTP status codes and error messages
3. **Rate Limiting**: Implemented per-customer limits
4. **Encryption**: Uses Erlang's `:crypto` module (same as Plug.Crypto)

### ⚠️ Potential Improvements

1. **API Key Rotation**: Currently no rotation mechanism
2. **Scoped Permissions**: All API keys have full access
3. **Audit Logging**: Limited tracking of API key usage
4. **Database Storage**: Currently using environment variables

## The X-Encryption-Key Approach

### Is This Standard for E2EE APIs?

**Yes and No:**

- **Standard Practice**: Client-generated keys for E2EE
- **Non-standard**: Sending key in header (vs key exchange protocols)
- **Trade-off**: Simplicity vs advanced key exchange

### Similar Approaches:
- **Tresor.io**: Client-side encryption with user keys
- **SpiderOak**: Zero-knowledge encryption
- **Tarsnap**: Client-side encryption keys

### Security Considerations:
1. ✅ Key never stored on server
2. ✅ True end-to-end encryption
3. ⚠️ Relies on HTTPS for key transport
4. ⚠️ No perfect forward secrecy

## Comparison with Industry Standards

### API Authentication Methods

1. **API Keys** (RSOLV's approach)
   - GitHub: `Authorization: token <token>`
   - Stripe: `Authorization: Bearer <key>`
   - SendGrid: `Authorization: Bearer <key>`

2. **OAuth 2.0** (More complex)
   - Google APIs
   - Microsoft Graph
   - Twitter API v2

3. **JWT Tokens** (Stateless sessions)
   - Auth0
   - Firebase
   - Many modern APIs

### RSOLV's Choice is Appropriate Because:
1. **Single-tenant**: Each customer has their own API key
2. **CI/CD Focus**: No need for OAuth flows
3. **Simplicity**: Easy to implement in GitHub Actions
4. **Performance**: No token validation overhead

## Recommendations

### Current Approach is Good ✅
- Appropriate for API-only service
- Follows industry patterns for developer tools
- Simple and secure for the use case

### Future Enhancements to Consider:
1. **API Key Metadata**: Add created_at, last_used_at, expires_at
2. **Multiple Keys**: Allow customers to have multiple keys
3. **Key Rotation API**: Endpoint to rotate keys programmatically
4. **Scoped Keys**: Read-only vs read-write permissions
5. **WebAuthn**: For dashboard access (if added later)

## Conclusion

RSOLV is **not** using phx.gen.auth patterns, and **that's correct**. The application is an API service, not a web application with browser users. The current approach:

1. ✅ Follows API industry standards (Bearer tokens)
2. ✅ Appropriate for the use case (CI/CD integrations)
3. ✅ Secure for the threat model (API clients, not browsers)
4. ✅ Simple to implement and use

The X-Encryption-Key approach for E2EE is a pragmatic choice that balances security with implementation simplicity, though more sophisticated key exchange could be added in the future.