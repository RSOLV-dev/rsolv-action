defmodule Rsolv.Security.Patterns.Javascript.JwtNoneAlgorithm do
  @moduledoc """
  JWT None Algorithm vulnerability detection for JavaScript/TypeScript.

  The "none" algorithm vulnerability in JWT libraries allows attackers to bypass
  authentication by crafting tokens that specify "alg": "none" in the header.
  If the JWT verification doesn't explicitly validate allowed algorithms, the
  library might accept these unsigned tokens as valid.

  ## Vulnerability Details

  When JWT libraries verify tokens without enforcing a list of allowed algorithms,
  an attacker can create a token with:
  - Header: {"alg": "none", "typ": "JWT"}
  - Payload: Any claims they want
  - Signature: Empty or omitted

  The library sees "none" as a valid algorithm and skips signature verification,
  accepting the forged token.

  ### Attack Example
  ```javascript
  // Vulnerable code
  const decoded = jwt.verify(token, secret);
  // If token has "alg": "none", signature check is skipped!

  // Attacker creates token:
  // Header: {"alg": "none", "typ": "JWT"}
  // Payload: {"sub": "admin", "role": "admin"}
  // No signature needed!
  ```
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @doc """
  Returns the pattern definition for JWT none algorithm vulnerability.

  ## Examples

      iex> pattern = Rsolv.Security.Patterns.Javascript.JwtNoneAlgorithm.pattern()
      iex> pattern.id
      "js-jwt-none-algorithm"

      iex> pattern = Rsolv.Security.Patterns.Javascript.JwtNoneAlgorithm.pattern()
      iex> pattern.severity
      :high

      iex> pattern = Rsolv.Security.Patterns.Javascript.JwtNoneAlgorithm.pattern()
      iex> vulnerable = "jwt.verify(token, secret)"
      iex> Regex.match?(pattern.regex, vulnerable)
      true

      iex> pattern = Rsolv.Security.Patterns.Javascript.JwtNoneAlgorithm.pattern()
      iex> safe = "jwt.verify(token, secret, {algorithms: ['HS256']})"
      iex> Regex.match?(pattern.regex, safe)
      false
  """
  def pattern do
    %Pattern{
      id: "js-jwt-none-algorithm",
      name: "JWT None Algorithm Vulnerability",
      description: "JWT verification without algorithm validation can be bypassed",
      type: :authentication,
      severity: :high,
      languages: ["javascript", "typescript"],
      # Matches jwt.verify without algorithms option or with options but no algorithms
      regex:
        ~r/jwt\.verify\s*\([^,)]+,[^,)]+(?:,\s*\{(?![^}]*algorithms)[^}]*\}|(?:,\s*[^{])?)?\s*\)/i,
      cwe_id: "CWE-347",
      owasp_category: "A02:2021",
      recommendation: "Always specify allowed algorithms in JWT verification.",
      test_cases: %{
        vulnerable: [
          ~S|jwt.verify(token, secret)|,
          ~S|jwt.verify(token, publicKey, {issuer: 'myapp'})|,
          ~S|const decoded = jwt.verify(req.headers.authorization, key)|
        ],
        safe: [
          ~S|jwt.verify(token, secret, {algorithms: ['HS256']})|,
          ~S|jwt.verify(token, publicKey, {algorithms: ['RS256'], issuer: 'myapp'})|,
          ~S|jwt.verify(token, key, {algorithms: ['HS256', 'HS384', 'HS512']})|
        ]
      }
    }
  end

  @doc """
  Returns comprehensive vulnerability metadata for JWT none algorithm vulnerability.

  Includes CVE examples, attack vectors, and detailed remediation guidance
  specific to JWT algorithm confusion attacks.
  """
  def vulnerability_metadata do
    %{
      description: """
      The JWT "none" algorithm vulnerability occurs when JWT verification libraries
      accept tokens with "alg": "none" in the header without proper validation.
      This completely bypasses signature verification, allowing attackers to forge
      arbitrary tokens. The vulnerability exists because the JWT specification
      originally included "none" as a valid algorithm for use cases where the
      integrity of the token is ensured by other means. However, if a JWT library
      accepts "none" without explicit configuration, it creates a critical
      authentication bypass.

      The attack is particularly dangerous because:
      1. No cryptographic knowledge is required
      2. Tokens can be crafted with simple base64 encoding
      3. The vulnerability is often silent - no errors are thrown
      4. It bypasses all signature-based security measures
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-347",
          title: "Improper Verification of Cryptographic Signature",
          url: "https://cwe.mitre.org/data/definitions/347.html"
        },
        %{
          type: :owasp,
          id: "A02:2021",
          title: "OWASP Top 10 2021 - A02 Cryptographic Failures",
          url: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
        },
        %{
          type: :research,
          id: "auth0_jwt_vulnerabilities",
          title: "Critical vulnerabilities in JSON Web Token libraries",
          url: "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"
        },
        %{
          type: :research,
          id: "jwt_security_best_practices",
          title: "JWT Security Best Practices",
          url: "https://datatracker.ietf.org/doc/html/rfc8725"
        },
        %{
          type: :npm_advisory,
          id: "jsonwebtoken_algorithms",
          title: "node-jsonwebtoken Algorithm Confusion Documentation",
          url: "https://github.com/auth0/node-jsonwebtoken#algorithms-supported"
        }
      ],
      attack_vectors: [
        "Basic none algorithm: Header {\"alg\": \"none\"}, no signature required",
        "Case variations: {\"alg\": \"None\"}, {\"alg\": \"NONE\"}, {\"alg\": \"nOnE\"}",
        "Algorithm substitution: Change RS256 to none after obtaining public key",
        "Downgrade attack: Force system to accept none when other algs fail",
        "Token manipulation: Modify existing valid token to use none algorithm",
        "Library confusion: Exploit differences between JWT libraries",
        "Chained with other attacks: Combine with SQL injection to insert forged tokens"
      ],
      real_world_impact: [
        "Complete authentication bypass - login as any user",
        "Privilege escalation - grant admin roles via forged tokens",
        "Account takeover - create tokens for other users",
        "Data breach - access protected resources without authentication",
        "Audit trail manipulation - forge tokens with false timestamps",
        "Multi-tenant compromise - access other organizations' data",
        "Session hijacking - create persistent valid sessions"
      ],
      cve_examples: [
        %{
          id: "CVE-2015-2951",
          description:
            "The node-jsonwebtoken library before 4.2.2 allows remote attackers to bypass authentication via an 'alg':'none' header",
          severity: "critical",
          cvss: 9.8,
          note: "Original discovery that led to widespread patches across JWT libraries"
        },
        %{
          id: "CVE-2016-10555",
          description:
            "The jsjws library before 0.1.3 allows remote attackers to bypass authentication by specifying 'none' algorithm",
          severity: "critical",
          cvss: 9.8,
          note: "Demonstrated the vulnerability was widespread across implementations"
        },
        %{
          id: "CVE-2018-0114",
          description:
            "node-jose before 0.11.0 allows attackers to bypass authentication using 'none' algorithm",
          severity: "critical",
          cvss: 9.8,
          note: "Shows the vulnerability persisted years after initial discovery"
        },
        %{
          id: "CVE-2022-23529",
          description:
            "node-jsonwebtoken before 9.0.0 has insecure default for JWT verification allowing 'none' algorithm",
          severity: "high",
          cvss: 7.5,
          note: "Recent example showing the issue continues to affect new code"
        }
      ],
      detection_notes: """
      This pattern detects jwt.verify() calls that don't explicitly specify allowed
      algorithms. The regex uses negative lookahead to ensure 'algorithms' is not
      present in the options object. Key detection points:
      1. jwt.verify with only token and secret parameters
      2. jwt.verify with options object but no algorithms property
      3. Common vulnerable patterns from popular tutorials

      The pattern must be careful not to match:
      - jwt.sign() or other non-verify methods
      - Calls that include algorithms in the options
      - Comments or string literals containing jwt.verify
      """,
      safe_alternatives: [
        "Always specify algorithms: jwt.verify(token, secret, {algorithms: ['HS256']})",
        "Use asymmetric algorithms when possible: {algorithms: ['RS256', 'ES256']}",
        "Implement algorithm allowlists at application level",
        "Use JWT libraries with secure defaults (jwks-rsa, jose)",
        "Validate algorithm matches expected type (symmetric vs asymmetric)",
        "Consider PASETO as an alternative to JWT",
        "Implement additional token validation (issuer, audience, expiry)"
      ],
      additional_context: %{
        common_mistakes: [
          "Assuming JWT libraries have secure defaults",
          "Only validating token expiration without algorithm checks",
          "Mixing symmetric and asymmetric algorithms in one system",
          "Not updating JWT libraries to patched versions",
          "Copy-pasting jwt.verify() from tutorials without options"
        ],
        secure_patterns: [
          "Create a centralized JWT verification function with hardcoded algorithms",
          "Use environment-specific algorithm configuration",
          "Implement JWT middleware that enforces algorithm validation",
          "Regular security audits of JWT implementation",
          "Monitor for tokens with unexpected algorithms in production"
        ],
        library_specific: %{
          jsonwebtoken: [
            "Version 9.0.0+ has secure defaults but explicit algorithms still recommended",
            "Use jwt.verify(token, secret, {algorithms: ['HS256'], complete: true})",
            "Consider using asymmetric algorithms for better security"
          ],
          jose: [
            "More secure by default but still specify allowed algorithms",
            "Use JWKS with algorithm specified in key metadata",
            "Leverage built-in algorithm validation features"
          ],
          express_jwt: [
            "Configure algorithms in middleware: jwt({secret, algorithms: ['HS256']})",
            "Use credentialsRequired: true to enforce authentication",
            "Implement custom isRevoked function for token blacklisting"
          ]
        }
      }
    }
  end

  @doc """
  Check if this pattern applies to a file based on its path and content.

  Applies to JavaScript/TypeScript files that might use JWT verification.
  """
  def applies_to_file?(file_path, content) do
    js_ts_file = String.match?(file_path, ~r/\.(js|jsx|ts|tsx|mjs|cjs)$/i)

    if content && js_ts_file do
      # Check if file likely contains JWT operations
      String.contains?(content, "jwt") || String.contains?(content, "jsonwebtoken")
    else
      # Just check file extension
      js_ts_file
    end
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual vulnerabilities and:
  - JWT verification with algorithms properly specified
  - Test code that might use simplified verification
  - JWT operations other than verify (sign, decode)
  - Code comments or examples mentioning jwt.verify

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Javascript.JwtNoneAlgorithm.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]

      iex> enhancement = Rsolv.Security.Patterns.Javascript.JwtNoneAlgorithm.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "CallExpression"

      iex> enhancement = Rsolv.Security.Patterns.Javascript.JwtNoneAlgorithm.ast_enhancement()
      iex> enhancement.ast_rules.callee_pattern
      "jwt.verify"

      iex> enhancement = Rsolv.Security.Patterns.Javascript.JwtNoneAlgorithm.ast_enhancement()
      iex> enhancement.min_confidence
      0.7

      iex> enhancement = Rsolv.Security.Patterns.Javascript.JwtNoneAlgorithm.ast_enhancement()
      iex> "has_algorithms_option" in Map.keys(enhancement.confidence_rules.adjustments)
      true
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        callee_pattern: "jwt.verify",
        # Must be missing algorithms in options
        argument_analysis: %{
          # Two args = definitely vulnerable
          has_three_arguments: false,
          missing_algorithms_option: true,
          third_arg_is_object: true,
          object_missing_algorithms: true
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/examples/, ~r/docs/],
        # Middleware enforces algorithms
        exclude_if_algorithms_enforced: true,
        # Custom wrapper with algorithms
        exclude_if_wrapped_securely: true,
        # Libraries with better defaults
        safe_jwt_libraries: ["jose", "jwks-rsa", "@panva/jose"]
      },
      confidence_rules: %{
        base: 0.4,
        adjustments: %{
          # jwt.verify(token, secret) - very likely vulnerable
          "no_options_object" => 0.4,
          # Has options but no algorithms
          "no_algorithms_option" => 0.3,
          # Explicitly sets algorithms - safe
          "has_algorithms_option" => -0.9,
          # Test code often simplified
          "in_test_code" => -0.5,
          # Using library with secure defaults
          "using_safe_library" => -0.6,
          # Might have central validation
          "wrapped_in_function" => -0.3
        }
      },
      min_confidence: 0.7
    }
  end
end
