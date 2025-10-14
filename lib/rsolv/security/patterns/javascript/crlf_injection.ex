defmodule Rsolv.Security.Patterns.JavaScript.CrlfInjection do
  @moduledoc """
  Pattern for detecting CRLF injection vulnerabilities in JavaScript/Node.js code.

  CRLF injection occurs when user input containing CR (\\r) and LF (\\n) characters
  is used in HTTP headers without sanitization, potentially allowing header injection
  or response splitting attacks.

  CWE-93: Improper Neutralization of CRLF Sequences
  OWASP: A03:2021 - Injection
  """

  use Rsolv.Security.Patterns.PatternBase

  alias Rsolv.Security.Pattern

  @impl true
  def pattern do
    meta = metadata()
    %Pattern{
      id: meta.id,
      name: meta.name,
      description: meta.description,
      type: String.to_existing_atom(meta.type),
      severity: String.to_existing_atom(meta.severity),
      languages: meta.languages,
      regex: hd(regex_patterns()),  # Use first pattern as primary
      cwe_id: meta.cwe_id,
      owasp_category: meta.owasp_category,
      recommendation: recommendation(),
      test_cases: test_cases()
    }
  end

  def metadata do
    %{
      id: "javascript-crlf-injection",
      name: "CRLF Injection in HTTP Headers",
      type: "crlf_injection",
      severity: "high",
      languages: ["javascript", "typescript"],
      cwe_id: "CWE-93",
      owasp_category: "A03:2021",
      description: "User input is used in HTTP headers without sanitization, potentially allowing header injection"
    }
  end


  def regex_patterns do
    [
      # setHeader with user input
      ~r/\.setHeader\s*\([^,]+,[^)]*\b(req|request|params|query|body|headers)\b/i,

      # writeHead with user input in headers object
      ~r/\.writeHead\s*\([^,]+,\s*\{[^}]*\b(req|request|params|query|body|headers)\b/i,

      # Express res.set/header with user input
      ~r/res\.(set|header)\s*\([^,]+,[^)]*\b(req|request|params|query|body|headers)\b/i,

      # res.write with user input (potential for header injection if headers not sent)
      ~r/res\.write\s*\([^)]*[\+`][^)]*\b(req|request|params|query|body|headers)\b/i,

      # Cookie setting with user input
      ~r/Set-Cookie['"]\s*,[^)]*[\+`][^)]*\b(req|request|params|query|body)\b/i,

      # decodeURIComponent on user input used in headers (can decode %0d%0a)
      ~r/\.setHeader\s*\([^,]+,[^)]*decodeURIComponent\s*\([^)]*\b(req|request|params|query)\b/i,

      # Response headers with concatenation/template literals
      ~r/res\.(setHeader|header|set)\s*\([^,]+,\s*[`'][^`']*\$\{[^}]*\b(req|request|params|query|body)\b/i,

      # Location header specifically (common for CRLF attacks)
      ~r/\.setHeader\s*\(['"]Location['"]\s*,[^)]*\b(req|request|params|query)\b/i
    ]
  end


  def test_cases do
    %{
      vulnerable: [
        ~S|res.setHeader('Location', req.query.redirect);|,
        ~S|res.setHeader('X-User', req.params.username);|,
        ~S|res.header('X-Custom-Header', req.body.custom);|,
        ~S|res.writeHead(200, { 'Content-Type': req.headers['content-type'] });|,
        ~S|res.setHeader('Set-Cookie', 'session=' + req.body.session);|,
        ~S|res.set('X-Forwarded-For', 'proxy,' + req.headers['user-agent']);|,
        ~S|res.setHeader('X-Data', decodeURIComponent(req.query.data));|
      ],
      safe: [
        ~S|res.setHeader('Content-Type', 'application/json');|,
        ~S|res.setHeader('X-Frame-Options', 'DENY');|,
        ~S|res.setHeader('X-User', sanitizeHeaderValue(req.params.username));|,
        ~S|res.setHeader('X-Data', encodeURIComponent(req.query.data));|,
        ~S|res.setHeader('X-Value', req.query.value.replace(/[\r\n]/g, ''));|,
        ~S|res.setHeader('Location', validateRedirectUrl(req.query.redirect));|
      ]
    }
  end


  def recommendation do
    """
    Validate and sanitize all user input used in HTTP headers:

    1. Remove or encode CR (\\r) and LF (\\n) characters
    2. Validate input against expected patterns
    3. Use allow-lists for redirect URLs
    4. Encode special characters appropriately
    5. Never decode URL-encoded input before using in headers

    Example safe header handling:
    ```javascript
    // Sanitize header values
    function sanitizeHeaderValue(value) {
      // Remove CRLF characters
      return value.replace(/[\\r\\n]/g, '');
    }

    // Instead of:
    res.setHeader('X-User', req.query.username);

    // Use:
    res.setHeader('X-User', sanitizeHeaderValue(req.query.username));

    // For redirects, validate the URL:
    const allowedHosts = ['example.com', 'app.example.com'];
    function validateRedirectUrl(url) {
      const parsed = new URL(url);
      if (!allowedHosts.includes(parsed.hostname)) {
        return '/';
      }
      return url.replace(/[\\r\\n]/g, '');
    }
    ```
    """
  end


  def ast_rules do
    %{
      javascript: %{
        call_expression: %{
          callee: %{
            member_expression: %{
              object: ["res", "response"],
              property: ["setHeader", "header", "set", "writeHead", "write"]
            }
          },
          arguments: %{
            contains_user_input: true,
            header_value_position: 2
          }
        }
      }
    }
  end


  def context_rules do
    %{
      exclude_paths: [
        "**/test/**",
        "**/tests/**",
        "**/spec/**",
        "**/__tests__/**"
      ],
      safe_if_wrapped: [
        "sanitizeHeaderValue",
        "encodeURIComponent",
        "validateRedirectUrl",
        "escapeHeader"
      ],
      safe_patterns: [
        # Already removes CRLF
        ~r/\.replace\s*\(\s*\/\[\\r\\n\]\/g/
      ]
    }
  end


  def confidence_rules do
    %{
      base: 80,
      adjustments: %{
        "has_crlf_removal" => -50,  # .replace(/[\r\n]/g, '')
        "uses_encoding" => -30,     # encodeURIComponent
        "location_header" => +10,    # Location header is higher risk
        "cookie_header" => +10       # Set-Cookie is higher risk
      }
    }
  end

  @impl true
  def ast_enhancement do
    %{
      ast_rules: ast_rules(),
      context_rules: context_rules(),
      confidence_rules: confidence_rules(),
      min_confidence: 0.6
    }
  end
end