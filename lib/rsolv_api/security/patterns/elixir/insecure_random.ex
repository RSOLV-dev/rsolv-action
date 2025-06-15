defmodule RsolvApi.Security.Patterns.Elixir.InsecureRandom do
  @moduledoc """
  Detects insecure random number generation in Elixir.
  
  This pattern identifies the use of predictable pseudo-random number generators (PRNGs)
  like :rand.uniform and Enum.random for security-sensitive operations where cryptographically
  secure random numbers are required.
  
  ## Vulnerability Details
  
  Standard random functions in Elixir/Erlang are designed for speed and distribution, not
  security. They use predictable algorithms that can be reverse-engineered or predicted by
  attackers, making them unsuitable for:
  - Session tokens
  - Password reset tokens  
  - API keys
  - Cryptographic nonces
  - Any security-sensitive random values
  
  ### Attack Example
  
  Vulnerable code:
  ```elixir
  # Predictable token generation
  reset_token = :rand.uniform(999999)
  ```
  
  An attacker who knows the seed or can observe enough outputs can predict future tokens.
  
  ### Safe Alternative
  
  Safe code:
  ```elixir
  # Cryptographically secure random
  reset_token = :crypto.strong_rand_bytes(32) |> Base.encode64()
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "elixir-insecure-random",
      name: "Insecure Random Number Generation",
      description: "Using :rand for security-sensitive random values",
      type: :insecure_random,
      severity: :high,
      languages: ["elixir"],
      regex: [
        # :rand.uniform usage (common insecure pattern)
        ~r/:rand\.uniform\s*\(/,
        # Enum.random usage (also predictable)
        ~r/Enum\.random\s*\(/,
        # :random module (deprecated but still seen)
        ~r/:random\.uniform\s*\(/,
        # Detecting potential security contexts with weak random
        ~r/(?:token|key|password|secret|nonce|salt|session|api_key)\s*=\s*(?::rand\.uniform|Enum\.random|:random\.uniform)/i,
        # Integer.to_string with :rand.uniform (common token pattern)
        ~r/Integer\.to_string\s*\(\s*:rand\.uniform/,
        # Base encoding with weak random
        ~r/Base\.(?:encode64|encode32|encode16|url_encode64)\s*\(\s*<<:rand\.uniform/
      ],
      default_tier: :public,
      cwe_id: "CWE-338",
      owasp_category: "A02:2021",
      recommendation: "Use :crypto.strong_rand_bytes/1 for cryptographically secure random values",
      test_cases: %{
        vulnerable: [
          ~S|token = :rand.uniform(1000000)|,
          ~S|session_id = :rand.uniform(999999999)|,
          ~S|api_key = Enum.random(1..999999)|,
          ~S|reset_token = Enum.random(100000..999999)|,
          ~S|:random.uniform(100000)|,
          ~S|password_reset_token = Integer.to_string(:rand.uniform(999999))|
        ],
        safe: [
          ~S|token = :crypto.strong_rand_bytes(32)|,
          ~S":crypto.strong_rand_bytes(16) |> Base.encode64()",
          ~S|id = System.unique_integer([:positive])|,
          ~S|uuid = Ecto.UUID.generate()|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Insecure random number generation in Elixir occurs when developers use predictable
      pseudo-random number generators (PRNGs) like :rand.uniform/1 or Enum.random/1 for
      security-sensitive operations. These functions use algorithms designed for speed and
      statistical distribution, not cryptographic security. The Mersenne Twister algorithm
      used by :rand can be reverse-engineered after observing only 624 outputs, allowing
      attackers to predict all future values. This vulnerability is particularly dangerous
      for session tokens, password reset codes, API keys, and cryptographic nonces.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-338",
          title: "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
          url: "https://cwe.mitre.org/data/definitions/338.html"
        },
        %{
          type: :owasp,
          id: "A02:2021",
          title: "OWASP Top 10 2021 - A02 Cryptographic Failures",
          url: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
        },
        %{
          type: :research,
          id: "erlang_random_security",
          title: "The Adventures of Generating Random Numbers in Erlang and Elixir",
          url: "https://hashrocket.com/blog/posts/the-adventures-of-generating-random-numbers-in-erlang-and-elixir"
        },
        %{
          type: :research,
          id: "fluid_attacks_random",
          title: "Insecure Generation of Random Numbers - Elixir",
          url: "https://help.fluidattacks.com/portal/en/kb/articles/criteria-fixes-elixir-034"
        }
      ],
      attack_vectors: [
        "Seed prediction: If attacker knows the seed, all future values are predictable",
        "State recovery: Observing 624 consecutive :rand outputs allows full state recovery",
        "Timing attacks: Seeds based on timestamps can be brute-forced",
        "Parallel prediction: Multiple processes with similar seeds generate similar sequences",
        "Statistical analysis: Weak PRNGs fail randomness tests, revealing patterns"
      ],
      real_world_impact: [
        "Session hijacking through predictable session tokens",
        "Account takeover via guessable password reset tokens",
        "API key compromise allowing unauthorized access",
        "Cryptographic breaks due to predictable nonces",
        "Multi-factor authentication bypass with predictable codes"
      ],
      cve_examples: [
        %{
          id: "CVE-2021-3538",
          description: "Predictable UUID generation due to insecure randomness",
          severity: "high",
          cvss: 7.5,
          note: "Demonstrates how weak randomness in identifier generation leads to security bypass"
        },
        %{
          id: "CVE-2008-0166",
          description: "Debian OpenSSL predictable random number generator",
          severity: "critical",
          cvss: 10.0,
          note: "Historic example showing catastrophic impact of weak randomness in cryptography"
        }
      ],
      detection_notes: """
      This pattern detects common insecure random generation including:
      - Direct :rand.uniform/1 and Enum.random/1 usage
      - Deprecated :random module usage
      - Security-sensitive variable names with weak random assignment
      - Common token generation patterns using Integer.to_string
      """,
      safe_alternatives: [
        "Use :crypto.strong_rand_bytes/1 for all security-sensitive randomness",
        "For tokens: :crypto.strong_rand_bytes(32) |> Base.url_encode64()",
        "For UUIDs: Use Ecto.UUID.generate() which uses crypto internally",
        "For unique IDs: System.unique_integer([:positive, :monotonic])",
        "Never use :rand for passwords, tokens, keys, or cryptographic operations"
      ],
      additional_context: %{
        common_mistakes: [
          "Using :rand.seed/1 thinking it makes output cryptographically secure",
          "Assuming Enum.random is secure because it's in standard library",
          "Using timestamp-based seeds for 'uniqueness'",
          "Mixing :rand output with other data thinking it adds security"
        ],
        secure_patterns: [
          "Always use :crypto module for security-sensitive randomness",
          "Generate sufficient entropy (minimum 128 bits for tokens)",
          "Use Base.url_encode64 for URL-safe token encoding",
          "Consider using established libraries like Guardian for token management"
        ]
      }
    }
  end
  
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        random_analysis: %{
          check_random_usage: true,
          insecure_functions: [":rand.uniform", "Enum.random", ":random.uniform"],
          secure_functions: [":crypto.strong_rand_bytes", "System.unique_integer", "Ecto.UUID.generate"],
          check_variable_context: true
        },
        context_analysis: %{
          check_assignment_target: true,
          security_indicators: ["token", "key", "password", "secret", "nonce", "salt", "session", "api", "auth", "csrf"],
          check_function_name: true
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/_test\.exs$/],
        security_contexts: ["token", "password", "secret", "key", "session", "auth", "api", "nonce", "salt", "csrf"],
        exclude_if_game_context: true,
        game_indicators: ["dice", "game", "random_", "shuffle", "sample"]
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "in_security_context" => 0.4,
          "uses_crypto_module" => -0.9,
          "in_test_code" => -1.0,
          "in_game_context" => -0.7,
          "has_security_variable_name" => 0.3
        }
      },
      min_confidence: 0.7
    }
  end
end