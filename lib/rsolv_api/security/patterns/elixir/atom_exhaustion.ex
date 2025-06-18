defmodule RsolvApi.Security.Patterns.Elixir.AtomExhaustion do
  @moduledoc """
  Atom Table Exhaustion vulnerability pattern for Elixir applications.

  This pattern detects potentially dangerous operations that can lead to atom
  table exhaustion, causing the entire VM to crash when the atom limit is reached.

  ## Vulnerability Details

  Atom table exhaustion occurs when:
  - Converting user input directly to atoms using `String.to_atom/1` or `binary_to_atom/1`
  - JSON decoding with `:atoms` key conversion from untrusted data
  - Creating atoms dynamically at runtime from external input
  - Pattern matching or case statements that create atoms from user data
  - String interpolation that creates atom keys from user input

  ## Technical Impact

  Resource exhaustion and system crash through:
  - Unlimited atom creation from malicious input leading to VM crash
  - Memory exhaustion as atoms are never garbage collected
  - Complete system unavailability when atom table limit is reached (default: 1,048,576)
  - Potential for targeted DoS attacks with relatively few requests
  - Cascading failures across connected nodes in distributed systems

  ## Examples

  Vulnerable patterns:
  ```elixir
  # VULNERABLE - direct user input to atom conversion
  String.to_atom(user_input)
  
  # VULNERABLE - JSON decode with atom keys from untrusted source
  Jason.decode!(user_json, keys: :atoms)
  
  # VULNERABLE - interpolation with user data  
  String.to_atom("prefix_\#{user_controlled_value}")
  
  # VULNERABLE - pattern matching with dynamic atoms
  case String.to_atom(user_role) do
    :admin -> :ok
    _ -> :error
  end
  ```

  Safe alternatives:
  ```elixir
  # SAFE - only use existing atoms
  String.to_existing_atom(validated_input)
  
  # SAFE - JSON decode with string keys (default)
  Jason.decode!(user_json)
  
  # SAFE - validate against known atoms first
  if user_role in ["admin", "user", "guest"] do
    String.to_existing_atom(user_role)
  end
  
  # SAFE - use :atoms! for known static keys only
  Jason.decode!(trusted_config, keys: :atoms!)
  ```

  ## Attack Scenarios

  1. **Direct DoS Attack**: Attacker sends approximately 1 million requests with
     unique values that get converted to atoms, exhausting the atom table

  2. **JSON Payload Attack**: Malicious JSON with many unique keys processed
     with `keys: :atoms` option rapidly fills the atom table

  3. **Amplification Attack**: Single request with large JSON containing
     thousands of unique keys causes rapid atom creation

  4. **Persistence Attack**: Atoms remain in memory for VM lifetime, making
     even slow attacks eventually successful

  ## References

  - Elixir Security: Atom Exhaustion DoS: https://paraxial.io/blog/atom-dos
  - EEF Security WG - Preventing Atom Exhaustion: https://erlef.github.io/security-wg/secure_coding_and_deployment_hardening/atom_exhaustion.html
  - GHSA-mj35-2rgf-cv8p: OpenID Connect client Atom Exhaustion
  - CWE-400: Uncontrolled Resource Consumption
  - OWASP Top 10 2021 - A05: Security Misconfiguration
  """

  use RsolvApi.Security.Patterns.PatternBase

  @impl true
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "elixir-atom-exhaustion",
      name: "Atom Table Exhaustion Risk",
      description: "Unsafe atom creation from user input that can exhaust the atom table and crash the VM",
      type: :resource_exhaustion,
      severity: :high,
      languages: ["elixir"],
      frameworks: [],
      regex: [
        # JSON libraries with :atoms key conversion
        ~r/Jason\.decode!?\s*\([^,]+,\s*keys:\s*:atoms\s*\)/,
        ~r/Poison\.decode!?\s*\([^,]+,\s*keys:\s*:atoms\s*\)/,
        ~r/JSON\.decode!?\s*\([^,]+,\s*keys:\s*:atoms\s*\)/,
        
        # Direct atom creation from user input patterns
        ~r/String\.to_atom\s*\(\s*[^)]*(?:user_|input|param|request|data)/i,
        ~r/binary_to_atom\s*\(\s*[^)]*(?:user_|input|param|request|data)/i,
        ~r/List\.to_atom\s*\(\s*[^)]*(?:user_|input|param|request|data)/i,
        
        # Atom creation with interpolation that might include user data
        ~r/String\.to_atom\s*\(\s*["'][^"']*#\{[^}]*\}/,
        ~r/binary_to_atom\s*\(\s*["'][^"']*#\{[^}]*\}/,
        
        # Pattern matching or case statements with dynamic atoms
        ~r/case\s+String\.to_atom\s*\(/,
        ~r/with\s+[^<]*<-\s*String\.to_atom\s*\(/,
        ~r/String\.to_atom\s*\([^)]+\)\s+do/,
        
        # Function calls that might create atoms from external input
        ~r/String\.to_atom\s*\(\s*(?!["']\w+["'])[^)]+\)/,
        ~r/binary_to_atom\s*\(\s*(?!["']\w+["'])[^)]+\)/
      ],
      default_tier: :ai,
      cwe_id: "CWE-400",
      owasp_category: "A05:2021",
      recommendation: "Use String.to_existing_atom/1, Jason.decode/1 without :atoms, or validate input against known atom lists",
      test_cases: %{
        vulnerable: [
          ~S|Jason.decode!(user_input, keys: :atoms)|,
          ~S|String.to_atom(user_input)|,
          ~S|String.to_atom("prefix_#{user_data}")|,
          ~S|case String.to_atom(user_role) do|
        ],
        safe: [
          ~S|Jason.decode!(user_input)|,
          ~S|String.to_existing_atom(validated_input)|,
          ~S|Jason.decode!(config, keys: :atoms!)|,
          ~S|binary_to_existing_atom(known_value)|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      attack_vectors: """
      1. Direct DoS Attack: Send ~1 million requests with unique atom values to crash VM
      2. JSON Payload Attack: Large JSON with many unique keys using keys: :atoms option
      3. Amplification Attack: Single request with thousands of unique JSON keys
      4. Persistence Attack: Slow but steady atom creation over time (atom table never garbage collected)
      """,
      business_impact: """
      Critical: Atom table exhaustion can cause:
      - Complete system crash and unavailability
      - Cascading failures in distributed systems  
      - Data loss from ungraceful shutdowns
      - Emergency restarts and service interruption
      - Potential for targeted DoS with minimal attacker resources
      """,
      technical_impact: """
      High: Resource exhaustion through:
      - VM crash when atom table limit exceeded (default: 1,048,576 atoms)
      - Memory exhaustion as atoms are never garbage collected
      - Complete loss of all processes and state in the VM
      - Inability to recover without full system restart
      - Potential distributed system failure propagation
      """,
      likelihood: "Medium: Common when processing untrusted JSON or user input without proper validation",
      cve_examples: [
        "GHSA-mj35-2rgf-cv8p: OpenID Connect client Atom Exhaustion vulnerability",
        "CWE-400: Uncontrolled Resource Consumption patterns",
        "Paraxial Security Research: Elixir/Phoenix DoS via Atom Exhaustion (2023)"
      ],
      compliance_standards: [
        "OWASP Top 10 2021 - A05: Security Misconfiguration",
        "NIST Cybersecurity Framework - DE.CM: Continuous Monitoring",
        "ISO 27001 - A.12.2: Protection against Malware"
      ],
      remediation_steps: """
      1. Replace String.to_atom/1 with String.to_existing_atom/1 for known atoms
      2. Use Jason.decode/1 without keys: :atoms for untrusted JSON
      3. Validate input against allowlists before atom conversion
      4. Use :atoms! only for trusted, static configuration data
      5. Implement input validation and rate limiting
      6. Monitor atom table usage in production systems
      """,
      prevention_tips: """
      1. Never convert untrusted user input directly to atoms at runtime
      2. Use string keys for JSON processing by default
      3. Validate all external input against known value sets
      4. Implement allowlists for any dynamic atom creation
      5. Use existing_atom functions when atom must already exist
      6. Configure atom table monitoring and alerting
      """,
      detection_methods: """
      1. Static code analysis for unsafe atom creation patterns
      2. Runtime monitoring of atom table size and growth
      3. Input validation testing with large/unique value sets
      4. Code review focusing on JSON processing and user input handling
      5. Load testing with atom exhaustion attack patterns
      """,
      safe_alternatives: """
      1. Use String.to_existing_atom/1 instead of String.to_atom/1
      2. Use Jason.decode/1 with string keys (default behavior)
      3. Use binary_to_existing_atom/1 for binary inputs
      4. Validate against known atom lists before conversion
      5. Use :atoms! option only for trusted, static configuration
      6. Implement proper input validation and sanitization
      """
    }
  end

  @impl true  
  def ast_enhancement do
    %{
      min_confidence: 0.8,
      context_rules: %{
        exclude_test_files: true,
        test_file_patterns: [
          ~r/_test\.exs$/,
          ~r/\/test\//,
          ~r/test_helper\.exs$/
        ],
        user_input_indicators: [
          "user_",
          "input",
          "params",
          "request",
          "data",
          "json",
          "payload"
        ],
        check_user_input_context: true,
        json_libraries: [
          "Jason",
          "Poison", 
          "JSON"
        ],
        unsafe_atom_functions: [
          "String.to_atom",
          "binary_to_atom",
          "List.to_atom"
        ]
      },
      confidence_rules: %{
        base: 0.8,
        adjustments: %{
          test_context_penalty: -0.6,
          user_input_bonus: 0.1,
          json_context_bonus: 0.1,
          interpolation_bonus: 0.05,
          pattern_matching_bonus: 0.1
        }
      },
      ast_rules: %{
        node_type: "atom_analysis",
        atom_analysis: %{
          check_atom_creation: true,
          check_user_input: true,
          atom_functions: ["String.to_atom", "binary_to_atom", "List.to_atom"],
          safe_functions: ["String.to_existing_atom", "binary_to_existing_atom"]
        },
        json_analysis: %{
          check_decode_options: true,
          check_keys_option: true,
          libraries: ["Jason", "Poison", "JSON"],
          unsafe_options: ["keys: :atoms"],
          safe_options: ["keys: :strings", "keys: :atoms!"]
        },
        context_analysis: %{
          check_user_input: true,
          check_interpolation: true,
          user_input_patterns: ["user_", "input", "params", "request", "data"],
          interpolation_indicators: ["#{", "}"]
        },
        pattern_analysis: %{
          check_case_statements: true,
          check_with_statements: true,
          check_function_calls: true,
          dynamic_atom_indicators: ["case", "with", "do"]
        }
      }
    }
  end
end