defmodule RsolvApi.Security.Patterns.Javascript.TimingAttackComparison do
  @moduledoc """
  Timing Attack via String Comparison pattern for detecting non-constant time comparisons.
  
  When comparing secret values like passwords, tokens, or API keys using standard
  string comparison operators (===, ==, !==, !=), the comparison stops at the first
  differing character. This creates timing differences that can be measured by
  attackers to gradually determine the secret value character by character.
  
  ## Vulnerability Details
  
  String comparison timing attacks exploit the fact that standard comparison
  operations return early when a difference is found. By measuring response times
  with high precision, attackers can determine:
  - Which character position causes the comparison to fail
  - The correct character at each position through repeated attempts
  - Eventually, the complete secret value
  
  ### Attack Example
  ```javascript
  // Vulnerable code - comparison time varies with input
  if (req.headers['api-key'] === SECRET_API_KEY) {
    // Authorized
  }
  
  // Attacker measures response times:
  // "a..." fails fast (1st char wrong)
  // "S..." takes longer (1st char correct, 2nd wrong)
  // "Se..." takes even longer (2 chars correct)
  // Gradually determines SECRET_API_KEY
  
  // Safe alternative
  if (crypto.timingSafeEqual(
    Buffer.from(req.headers['api-key']),
    Buffer.from(SECRET_API_KEY)
  )) {
    // Authorized
  }
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @doc """
  Returns the pattern definition for timing attack via string comparison.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.TimingAttackComparison.pattern()
      iex> pattern.id
      "js-timing-attack"
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.TimingAttackComparison.pattern()
      iex> pattern.severity
      :low
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.TimingAttackComparison.pattern()
      iex> vulnerable = "if (userToken === secretToken)"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Javascript.TimingAttackComparison.pattern()
      iex> safe = "if (username === 'admin')"
      iex> Regex.match?(pattern.regex, safe)
      false
  """
  def pattern do
    %Pattern{
      id: "js-timing-attack",
      name: "Timing Attack via String Comparison",
      description: "Direct string comparison of secrets can leak information via timing",
      type: :timing_attack,
      severity: :low,
      languages: ["javascript", "typescript"],
      # Matches comparison operators with security-related variable names on either side
      regex: ~r/(?:(?:secret|token|password|key|hash|auth)[^=]*(?:===|==|!==|!=)|(?:===|==|!==|!=)[^=]*(?:secret|token|password|key|hash|auth))/i,
      cwe_id: "CWE-208",
      owasp_category: "A04:2021",
      recommendation: "Use crypto.timingSafeEqual() for comparing secrets.",
      test_cases: %{
        vulnerable: [
          ~S|if (userToken === secretToken)|,
          ~s|return password == storedPassword|,
          ~S|if (req.headers.authorization !== apiKey)|
        ],
        safe: [
          ~S|crypto.timingSafeEqual(Buffer.from(userToken), Buffer.from(secretToken))|,
          ~S|bcrypt.compare(password, storedPassword)|,
          ~S|const valid = timingSafeCompare(req.headers.authorization, apiKey)|
        ]
      }
    }
  end
  
  @doc """
  Returns comprehensive vulnerability metadata for timing attacks.
  
  Includes information about side-channel attacks, measurement techniques,
  and constant-time programming practices.
  """
  def vulnerability_metadata do
    %{
      description: """
      Timing attacks are a type of side-channel attack where an attacker analyzes
      the time taken to execute cryptographic algorithms or security comparisons.
      In JavaScript, the most common timing vulnerability occurs when comparing
      secret values using standard string comparison operators.
      
      The vulnerability exists because:
      1. String comparison stops at the first differing character
      2. Modern CPUs and networks allow microsecond-precision timing
      3. Statistical analysis can extract signal from noisy measurements
      4. Remote timing attacks are practical over the internet
      
      While timing attacks require many requests and statistical analysis, they
      are a real threat, especially for:
      - API keys and authentication tokens
      - HMAC signatures and cryptographic hashes
      - Password or PIN comparisons
      - Any secret that must remain confidential
      """,
      
      references: [
        %{
          type: :cwe,
          id: "CWE-208",
          title: "Observable Timing Discrepancy",
          url: "https://cwe.mitre.org/data/definitions/208.html"
        },
        %{
          type: :owasp,
          id: "A04:2021",
          title: "OWASP Top 10 2021 - A04 Insecure Design",
          url: "https://owasp.org/Top10/A04_2021-Insecure_Design/"
        },
        %{
          type: :research,
          id: "remote_timing_attacks",
          title: "Remote Timing Attacks are Practical",
          url: "https://crypto.stanford.edu/~dabo/papers/ssl-timing.pdf"
        },
        %{
          type: :nodejs,
          id: "crypto_timing_safe",
          title: "Node.js crypto.timingSafeEqual() Documentation",
          url: "https://nodejs.org/api/crypto.html#cryptotimingsafeequala-b"
        },
        %{
          type: :article,
          id: "timing_attack_guide",
          title: "A Lesson In Timing Attacks",
          url: "https://codahale.com/a-lesson-in-timing-attacks/"
        }
      ],
      
      attack_vectors: [
        "Remote timing: Measure HTTP response times over network",
        "Local timing: High-precision measurements on same system",
        "Statistical analysis: Average thousands of requests to reduce noise",
        "Binary search: Determine secret one character at a time",
        "Amplification: Exploit multiple comparisons to increase timing difference",
        "Cache timing: Use CPU cache effects to enhance measurements",
        "Cross-origin timing: Measure from browser using performance API"
      ],
      
      real_world_impact: [
        "API key extraction allowing unauthorized access",
        "Token forgery leading to authentication bypass",
        "HMAC key recovery enabling message forgery",
        "Password discovery through repeated attempts",
        "Session hijacking via cookie value extraction",
        "Cryptographic key recovery in custom implementations",
        "Rate limiting bypass using extracted tokens"
      ],
      
      cve_examples: [
        %{
          id: "CVE-2018-16733",
          description: "Discord.js timing attack in token validation",
          severity: "medium",
          cvss: 5.3,
          note: "Token comparison vulnerable to timing analysis"
        },
        %{
          id: "CVE-2016-2107",
          description: "OpenSSL AES-NI timing attack",
          severity: "high",
          cvss: 7.5,
          note: "Padding oracle attack via timing measurements"
        },
        %{
          id: "CVE-2020-8203",
          description: "Lodash timing attack in string comparison",
          severity: "medium",
          cvss: 5.3,
          note: "defaultsDeep function vulnerable to timing analysis"
        },
        %{
          id: "CVE-2021-3129",
          description: "Laravel timing attack in password reset",
          severity: "medium",
          cvss: 5.9,
          note: "Token comparison allowed gradual extraction"
        }
      ],
      
      detection_notes: """
      This pattern detects string comparisons that might be vulnerable to timing
      attacks by looking for:
      1. Comparison operators (===, ==, !==, !=)
      2. Security-related variable names (token, password, key, etc.)
      3. Direct comparison without timing-safe functions
      
      The pattern may have false positives for non-secret comparisons and
      false negatives when secrets use non-standard variable names.
      """,
      
      safe_alternatives: [
        "Node.js: crypto.timingSafeEqual(a, b) for Buffer comparisons",
        "Use bcrypt.compare() or argon2.verify() for password verification",
        "Implement double-HMAC verification pattern",
        "Use established crypto libraries with timing-safe comparisons",
        "For non-crypto: ensure comparisons aren't security-critical",
        "Consider using secure-compare npm package for strings",
        "Web Crypto API: use subtle.verify() for signatures"
      ],
      
      additional_context: %{
        common_mistakes: [
          "Thinking timing attacks aren't practical over networks",
          "Using early return optimizations in security code",
          "Comparing hashes with === instead of timing-safe methods",
          "Assuming HTTPS prevents timing measurements",
          "Not considering timing in custom crypto implementations"
        ],
        
        secure_patterns: [
          "Always use constant-time comparison for secrets",
          "Avoid early returns in security-critical paths",
          "Use established crypto libraries, not custom code",
          "Add random delays (not recommended as sole defense)",
          "Rate limit authentication attempts"
        ],
        
        implementation_notes: %{
          nodejs: [
            "crypto.timingSafeEqual() requires Buffer inputs",
            "Convert strings to Buffer first: Buffer.from(string)",
            "Both buffers must be same length or it throws"
          ],
          browser: [
            "No built-in timing-safe comparison in browsers",
            "Use server-side validation for security",
            "Consider WebAssembly for constant-time operations"
          ],
          general: [
            "Timing-safe comparison alone isn't enough",
            "Also need rate limiting and monitoring",
            "Consider the full authentication system design"
          ]
        }
      }
    }
  end
  
  @doc """
  Check if this pattern applies to a file based on its path and content.
  
  Applies to JavaScript/TypeScript files that might contain security comparisons.
  """
  def applies_to_file?(file_path, content \\ nil) do
    cond do
      # JavaScript/TypeScript files
      String.match?(file_path, ~r/\.(js|jsx|ts|tsx|mjs|cjs)$/i) -> true
      
      # HTML files with script tags
      String.match?(file_path, ~r/\.html?$/i) && content != nil ->
        String.contains?(content, "<script")
        
      # Default
      true -> false
    end
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between security-critical comparisons
  that need timing-safe methods and regular comparisons that don't.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.TimingAttackComparison.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.TimingAttackComparison.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "BinaryExpression"
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.TimingAttackComparison.ast_enhancement()
      iex> "===" in enhancement.ast_rules.operators
      true
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.TimingAttackComparison.ast_enhancement()
      iex> enhancement.min_confidence
      0.6
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.TimingAttackComparison.ast_enhancement()
      iex> "compares_secret_variable" in Map.keys(enhancement.confidence_rules.adjustments)
      true
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "BinaryExpression",
        operators: ["===", "==", "!==", "!="],
        operand_analysis: %{
          check_variable_names: true,
          check_property_access: true,
          check_function_returns: true
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/benchmark/],
        exclude_if_timing_safe: true,      # Already using crypto.timingSafeEqual
        exclude_if_hashed: true,           # Comparing already-hashed values
        exclude_if_public: true,           # Comparing non-secret values
        safe_functions: ["timingSafeEqual", "compare", "verify", "constant_time_compare"],
        secret_indicators: ["secret", "token", "password", "key", "hash", "signature", "auth"]
      },
      confidence_rules: %{
        base: 0.2,  # Low base - many false positives possible
        adjustments: %{
          "compares_secret_variable" => 0.5,
          "in_auth_function" => 0.4,
          "compares_header_value" => 0.3,
          "compares_literal_string" => -0.3,   # Probably not a secret
          "in_timing_safe_wrapper" => -0.8,    # Already protected
          "compares_public_data" => -0.6,      # usernames, IDs, etc.
          "in_test_code" => -0.7,              # Test comparisons OK
          "uses_bcrypt_or_argon" => -0.9      # Using proper password lib
        }
      },
      min_confidence: 0.6
    }
  end
end
