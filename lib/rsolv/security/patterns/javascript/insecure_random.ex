defmodule Rsolv.Security.Patterns.Javascript.InsecureRandom do
  @moduledoc """
  Insecure Random Number Generation pattern for detecting Math.random() used for security.

  Math.random() is not cryptographically secure and produces predictable values that
  can be guessed or brute-forced by attackers. When used for security-sensitive purposes
  like generating tokens, session IDs, or cryptographic keys, it creates vulnerabilities
  that can lead to authentication bypass, session hijacking, or cryptographic failures.

  ## Vulnerability Details

  Math.random() uses a pseudo-random number generator (PRNG) with known weaknesses:
  - Predictable seed values based on system time
  - Limited entropy (typically 32-64 bits)
  - Observable patterns in output sequences
  - Vulnerable to state recovery attacks

  ### Attack Example
  ```javascript
  // Vulnerable code - predictable token generation
  const resetToken = Math.random().toString(36).substring(2);
  // Attacker can predict tokens by:
  // 1. Observing multiple tokens to determine PRNG state
  // 2. Brute-forcing the limited keyspace
  // 3. Exploiting timing correlations

  // Safe alternative
  const resetToken = crypto.randomBytes(32).toString('hex');
  ```
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @doc """
  Returns the pattern definition for insecure random number generation.

  ## Examples

      iex> pattern = Rsolv.Security.Patterns.Javascript.InsecureRandom.pattern()
      iex> pattern.id
      "js-insecure-random"
      
      iex> pattern = Rsolv.Security.Patterns.Javascript.InsecureRandom.pattern()
      iex> pattern.severity
      :medium
      
      iex> pattern = Rsolv.Security.Patterns.Javascript.InsecureRandom.pattern()
      iex> vulnerable = "const token = Math.random().toString()"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = Rsolv.Security.Patterns.Javascript.InsecureRandom.pattern()
      iex> safe = "const x = Math.random() * 100"
      iex> Regex.match?(pattern.regex, safe)
      false
  """
  def pattern do
    %Pattern{
      id: "js-insecure-random",
      name: "Insecure Random Number Generation",
      description: "Math.random() is not cryptographically secure",
      type: :insecure_random,
      severity: :medium,
      languages: ["javascript", "typescript"],
      # Matches Math.random() when used with security-related variable names
      regex:
        ~r/(?:token|key|password|secret|salt|nonce|session|auth)[^;]*=.*Math\.random\s*\(\s*\)|Math\.random\s*\(\s*\)[^;]*(?:token|key|password|secret|salt|nonce|session|auth)/i,
      cwe_id: "CWE-330",
      owasp_category: "A02:2021",
      recommendation:
        "Use crypto.randomBytes() or crypto.getRandomValues() for security purposes.",
      test_cases: %{
        vulnerable: [
          ~S|const token = Math.random().toString()|,
          ~S|const sessionId = Math.random() * 1000000|,
          ~S|const salt = Math.random().toString(36)|
        ],
        safe: [
          ~S|const token = crypto.randomBytes(32).toString('hex')|,
          ~S|const sessionId = crypto.randomUUID()|,
          ~S|const salt = crypto.getRandomValues(new Uint8Array(16))|
        ]
      }
    }
  end

  @doc """
  Returns comprehensive vulnerability metadata for insecure random number generation.

  Includes information about cryptographic weaknesses, attack techniques, and
  proper secure random number generation methods.
  """
  def vulnerability_metadata do
    %{
      description: """
      Math.random() is a pseudo-random number generator (PRNG) designed for general
      programming tasks, not cryptographic security. It uses algorithms like xorshift128+
      or MersenneTwister that are fast but predictable. When used for security-sensitive
      operations, this predictability allows attackers to guess or determine generated values.

      The vulnerability occurs when developers use Math.random() for:
      1. Session tokens or authentication tokens
      2. Password reset tokens
      3. API keys or secret identifiers
      4. Cryptographic nonces or initialization vectors
      5. Any value where unpredictability is a security requirement

      Attackers can exploit this by:
      - Predicting future values after observing some outputs
      - Recovering the internal state of the PRNG
      - Brute-forcing the limited entropy space
      - Exploiting time-based correlations in seed values
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-330",
          title: "Use of Insufficiently Random Values",
          url: "https://cwe.mitre.org/data/definitions/330.html"
        },
        %{
          type: :owasp,
          id: "A02:2021",
          title: "OWASP Top 10 2021 - A02 Cryptographic Failures",
          url: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
        },
        %{
          type: :owasp,
          id: "cryptographic_storage",
          title: "OWASP Cryptographic Storage Cheat Sheet",
          url:
            "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"
        },
        %{
          type: :research,
          id: "v8_random_predictability",
          title: "There's Math.random(), and then there's Math.random()",
          url: "https://v8.dev/blog/math-random"
        },
        %{
          type: :mozilla,
          id: "mdn_crypto_strong_random",
          title: "MDN: Crypto.getRandomValues()",
          url: "https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues"
        }
      ],
      attack_vectors: [
        "PRNG State Recovery: Observe outputs to determine internal state",
        "Seed Prediction: Exploit timestamp-based seeding on server start",
        "Brute Force: Limited entropy allows exhaustive search",
        "Timing Correlation: Multiple tokens generated close in time are related",
        "Cross-Origin Attacks: Browser Math.random() state may be observable",
        "VM Rollback: Virtual machine snapshots can repeat 'random' sequences",
        "Statistical Analysis: Detect patterns in large sets of tokens"
      ],
      real_world_impact: [
        "Authentication bypass through token prediction",
        "Session hijacking via predictable session IDs",
        "Password reset takeover with guessable tokens",
        "API key compromise allowing unauthorized access",
        "Cryptographic failures in custom implementations",
        "Financial loss from compromised payment tokens",
        "Privacy breaches through predictable anonymization"
      ],
      cve_examples: [
        %{
          id: "CVE-2015-0293",
          description: "OpenSSL used predictable random numbers in certain scenarios",
          severity: "high",
          cvss: 7.5,
          note: "Weak PRNG in cryptographic context led to key compromise"
        },
        %{
          id: "CVE-2008-0166",
          description: "Debian OpenSSL predictable random number generator",
          severity: "critical",
          cvss: 10.0,
          note: "Predictable keys affected SSH, SSL certificates, and more"
        },
        %{
          id: "CVE-2021-3449",
          description: "Node.js crypto.randomUUID() used Math.random() as fallback",
          severity: "medium",
          cvss: 5.3,
          note: "Fallback to insecure randomness when crypto unavailable"
        },
        %{
          id: "CVE-2020-28498",
          description: "Elliptic package using Math.random() for crypto operations",
          severity: "high",
          cvss: 7.5,
          note: "Cryptocurrency wallets generated with predictable keys"
        }
      ],
      detection_notes: """
      This pattern detects Math.random() usage in security contexts by looking for:
      1. Assignment to variables with security-related names
      2. Math.random() output used near security keywords
      3. Common patterns like toString(36) often used for tokens

      The pattern may miss cases where Math.random() is used indirectly or
      where security-sensitive variable names don't match common patterns.
      """,
      safe_alternatives: [
        "Node.js: crypto.randomBytes(size) for raw bytes",
        "Node.js: crypto.randomUUID() for UUID v4 generation",
        "Browser: crypto.getRandomValues(typedArray) for client-side",
        "Use established libraries: uuid, nanoid for identifiers",
        "For integers: crypto.randomInt(min, max) in Node.js 14.10+",
        "Web Crypto API: crypto.subtle.generateKey() for keys",
        "Consider hardware RNG for high-security applications"
      ],
      additional_context: %{
        common_mistakes: [
          "Using Math.random() + Date.now() thinking it adds entropy",
          "Seeding Math.random() with crypto values (doesn't help)",
          "Using Math.random() in loops thinking it's 'more random'",
          "Assuming server-side Math.random() is secure",
          "Using predictable transformations like base36 conversion"
        ],
        secure_patterns: [
          "Always use crypto module for security purposes",
          "Generate sufficient entropy (minimum 128 bits)",
          "Use constant-time comparisons for tokens",
          "Don't log or expose generated secrets",
          "Regenerate tokens on privilege changes"
        ],
        language_specific: %{
          nodejs: [
            "require('crypto').randomBytes(32) for tokens",
            "crypto.randomUUID() for unique identifiers",
            "Use promisified versions for async operations"
          ],
          browser: [
            "window.crypto.getRandomValues() for secure randoms",
            "Fallback handling for older browsers",
            "Consider SubtleCrypto for key generation"
          ],
          typescript: [
            "Type tokens as opaque types for safety",
            "Use branded types to prevent string confusion",
            "Leverage type system to enforce secure patterns"
          ]
        }
      }
    }
  end

  @doc """
  Check if this pattern applies to a file based on its path and content.

  Applies to JavaScript/TypeScript files that might use Math.random().
  """
  def applies_to_file?(file_path, content) do
    cond do
      # JavaScript/TypeScript files
      String.match?(file_path, ~r/\.(js|jsx|ts|tsx|mjs|cjs)$/i) ->
        true

      # HTML files with script tags
      String.match?(file_path, ~r/\.html?$/i) && content != nil ->
        String.contains?(content, "<script")

      # Default
      true ->
        false
    end
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between security-sensitive uses of Math.random()
  and legitimate non-security uses like animations, games, or UI effects.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Javascript.InsecureRandom.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.InsecureRandom.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "CallExpression"
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.InsecureRandom.ast_enhancement()
      iex> enhancement.ast_rules.callee_pattern
      "Math.random"
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.InsecureRandom.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.InsecureRandom.ast_enhancement()
      iex> "assigned_to_security_var" in Map.keys(enhancement.confidence_rules.adjustments)
      true
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        callee_pattern: "Math.random",
        usage_analysis: %{
          check_variable_name: true,
          check_context: true,
          check_transformations: true
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/demo/, ~r/example/],
        # Games legitimately use Math.random
        exclude_if_game_logic: true,
        # UI animations are fine
        exclude_if_animation: true,
        # Array randomization usually OK
        exclude_if_array_shuffle: true,
        security_indicators: [
          "token",
          "key",
          "secret",
          "password",
          "auth",
          "session",
          "nonce",
          "salt",
          "iv"
        ]
      },
      confidence_rules: %{
        # Low base - Math.random is very common
        base: 0.3,
        adjustments: %{
          "assigned_to_security_var" => 0.5,
          # Common token pattern
          "used_with_toString" => 0.3,
          # Often used for ID generation
          "used_with_substring" => 0.2,
          # Often for ranges/indices
          "multiplied_by_number" => -0.2,
          # Likely not security
          "in_math_expression" => -0.4,
          # DOM manipulation, animations
          "in_ui_context" => -0.6,
          # Tests might use it legitimately
          "in_test_file" => -0.8,
          # File deals with security
          "has_crypto_import" => 0.3
        }
      },
      min_confidence: 0.7
    }
  end
end
