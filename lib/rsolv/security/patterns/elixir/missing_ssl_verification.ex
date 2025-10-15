defmodule Rsolv.Security.Patterns.Elixir.MissingSslVerification do
  @moduledoc """
  Missing SSL Certificate Verification vulnerability pattern for Elixir applications.

  This pattern detects HTTP client configurations that disable SSL/TLS certificate
  verification, enabling man-in-the-middle (MITM) attacks and compromising the
  confidentiality and integrity of communications.

  ## Vulnerability Details

  Missing SSL verification occurs when applications disable certificate validation
  for HTTPS connections:
  - Using verify: :verify_none in SSL options
  - Using hackney: [:insecure] flag
  - Disabling certificate verification in HTTP client libraries
  - Accepting any certificate without validation

  ## Technical Impact

  Security risks through disabled certificate verification:
  - Man-in-the-middle attacks intercepting and modifying encrypted traffic
  - Credential theft through fake server impersonation
  - Data exposure via unverified SSL connections
  - Compliance violations for secure communication requirements

  ## Examples

  Vulnerable patterns:
  ```elixir
  # VULNERABLE - Disabled certificate verification
  HTTPoison.get!(url, [], ssl: [verify: :verify_none])

  # VULNERABLE - Insecure hackney option
  HTTPoison.post(url, body, headers, hackney: [:insecure])

  # VULNERABLE - Tesla with disabled verification
  Tesla.get(client, url, opts: [adapter: [ssl_options: [verify: :verify_none]]])

  # VULNERABLE - Req with disabled verification
  Req.get!(url, connect_options: [verify: :verify_none])
  ```

  Safe alternatives:
  ```elixir
  # SAFE - Default secure configuration
  HTTPoison.get!(url)

  # SAFE - Explicit peer verification
  HTTPoison.get!(url, [], ssl: [verify: :verify_peer])

  # SAFE - With custom CA certificates
  HTTPoison.get!(url, [], ssl: [
    verify: :verify_peer,
    cacerts: :certifi.cacerts()
  ])

  # SAFE - Development-only insecure option
  # if Mix.env() == :dev do
  #   HTTPoison.get!(url, [], hackney: [:insecure])
  # else
  #   HTTPoison.get!(url)
  # end
  ```

  ## Attack Scenarios

  1. **MITM Attack**: Attacker intercepts HTTPS traffic between client and server,
     presenting their own certificate which is accepted due to disabled verification

  2. **Credential Theft**: Attacker sets up fake API endpoint, steals authentication
     tokens and sensitive data sent by clients with disabled SSL verification

  3. **Data Manipulation**: Attacker modifies API responses in transit, injecting
     malicious data or commands without detection

  ## References

  - CWE-295: Improper Certificate Validation
  - OWASP Top 10 2021 - A07: Identification and Authentication Failures
  - Elixir HTTPoison Security Guidelines
  - Erlang SSL Application Reference Manual
  """

  use Rsolv.Security.Patterns.PatternBase

  @impl true
  def pattern do
    %Rsolv.Security.Pattern{
      id: "elixir-missing-ssl-verification",
      name: "Missing SSL Certificate Verification",
      description:
        "Disabled SSL verification enables MITM attacks compromising communication security",
      type: :authentication,
      severity: :high,
      languages: ["elixir"],
      frameworks: [],
      regex: [
        # SSL options with verify_none - exclude comments and @doc
        ~r/^(?!\s*#)(?!\s*@doc).*ssl:\s*\[.*verify:\s*:verify_none/m,

        # hackney insecure option - exclude comments and @doc
        ~r/^(?!\s*#)(?!\s*@doc).*hackney:\s*\[:insecure/m,

        # hackney ssl_options with verify_none - exclude comments and @doc
        ~r/^(?!\s*#)(?!\s*@doc).*hackney:\s*\[.*ssl_options:\s*\[.*verify:\s*:verify_none/m,

        # Tesla adapter with verify_none - exclude comments and @doc
        ~r/^(?!\s*#)(?!\s*@doc).*adapter:\s*\[.*ssl_options:\s*\[.*verify:\s*:verify_none/m,

        # Tesla adapter module syntax - exclude comments and @doc
        ~r/^(?!\s*#)(?!\s*@doc).*adapter\s+.*ssl_options:\s*\[.*verify:\s*:verify_none/m,

        # Tesla middleware syntax - exclude comments and @doc
        ~r/^(?!\s*#)(?!\s*@doc).*middleware\s+.*ssl_options:\s*\[.*verify:\s*:verify_none/m,

        # Req connect_options with verify_none - exclude comments and @doc
        ~r/^(?!\s*#)(?!\s*@doc).*connect_options:\s*\[.*verify:\s*:verify_none/m,

        # Config with verify_none - exclude comments and @doc
        ~r/^(?!\s*#)(?!\s*@doc).*config\s+.*ssl:\s*\[.*verify:\s*:verify_none/m,

        # Multi-line SSL options with verify_none - exclude comments and @doc
        ~r/^(?!\s*#)(?!\s*@doc).*verify:\s*:verify_none/m
      ],
      cwe_id: "CWE-295",
      owasp_category: "A07:2021",
      recommendation: "Always verify SSL certificates in production, use verify: :verify_peer",
      test_cases: %{
        vulnerable: [
          ~S|HTTPoison.get!(url, [], ssl: [verify: :verify_none])|,
          ~S|HTTPoison.post(url, body, headers, hackney: [:insecure])|,
          ~S|Tesla.get(client, url, opts: [adapter: [ssl_options: [verify: :verify_none]]])|,
          ~S|Req.get!(url, connect_options: [verify: :verify_none])|
        ],
        safe: [
          ~S|HTTPoison.get!(url)|,
          ~S|HTTPoison.get!(url, [], ssl: [verify: :verify_peer])|,
          ~S|HTTPoison.get!(url, [], ssl: [verify: :verify_peer, cacerts: :certifi.cacerts()])|,
          ~S|HTTPoison.get!(url, [], ssl: [versions: [:"tlsv1.2", :"tlsv1.3"]])|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      attack_vectors: """
      1. Man-in-the-middle (MITM) attacks intercepting HTTPS traffic by presenting fake certificates
      2. DNS hijacking combined with fake certificate presentation to redirect traffic to malicious servers
      3. BGP hijacking to route traffic through attacker-controlled infrastructure without detection
      4. WiFi evil twin attacks presenting fake certificates for API endpoints and services
      5. Certificate substitution attacks replacing legitimate certificates with attacker-controlled ones
      """,
      business_impact: """
      High: Missing SSL verification can result in:
      - Complete loss of confidentiality for all transmitted data including credentials and sensitive information
      - Data integrity compromise through undetected modification of API requests and responses
      - Regulatory compliance violations (PCI DSS, HIPAA, GDPR) requiring encrypted communications
      - Reputation damage from security breaches involving customer data exposure
      - Financial losses from fraud enabled by intercepted payment information and credentials
      """,
      technical_impact: """
      High: Disabled certificate verification enables:
      - Complete bypass of TLS/SSL security allowing traffic interception and modification
      - Credential theft through MITM attacks on authentication endpoints
      - Session hijacking by intercepting session tokens and cookies
      - Code injection through modified API responses containing malicious payloads
      - Data exfiltration via redirected connections to attacker-controlled servers
      """,
      likelihood:
        "Medium: Common in development environments but critical if deployed to production",
      cve_examples: [
        "CWE-295: Improper Certificate Validation",
        "CVE-2020-26262: Coturn TURN server certificate validation bypass",
        "CVE-2014-3566: POODLE attack on SSL 3.0",
        "CVE-2022-31692: Spring Security authorization bypass via missing verification"
      ],
      compliance_standards: [
        "OWASP Top 10 2021 - A07: Identification and Authentication Failures",
        "PCI DSS v4.0 - Requirement 4: Protect cardholder data with strong cryptography",
        "NIST SP 800-52: Guidelines for TLS Implementations",
        "ISO 27001 - A.10: Cryptography controls"
      ],
      remediation_steps: """
      1. Remove all instances of verify: :verify_none from production code
      2. Remove hackney: [:insecure] options from HTTP client calls
      3. Configure proper certificate verification with verify: :verify_peer
      4. Use certificate pinning for critical API endpoints
      5. Implement proper CA certificate bundle management (e.g., certifi)
      6. Use environment-specific configurations for development vs production
      """,
      prevention_tips: """
      1. Always use default secure configurations for HTTP clients (they verify by default)
      2. Never disable certificate verification in production environments
      3. Use environment checks for development-only insecure options
      4. Implement certificate pinning for high-security applications
      5. Regularly update CA certificate bundles to maintain trust chains
      6. Use static analysis tools to detect insecure SSL configurations
      """,
      detection_methods: """
      1. Static code analysis for SSL configuration patterns with verify_none
      2. Configuration file scanning for insecure SSL options
      3. Runtime monitoring for connections without certificate verification
      4. Security testing with invalid certificates to detect acceptance
      5. Code review focusing on HTTP client initialization and configuration
      """,
      safe_alternatives: """
      1. Default configuration: HTTPoison.get!(url) # Verifies by default
      2. Explicit verification: ssl: [verify: :verify_peer]
      3. Custom CA bundle: ssl: [verify: :verify_peer, cacerts: :certifi.cacerts()]
      4. Certificate pinning: ssl: [verify_fun: {&verify_cert/3, pin}]
      5. Development-only bypass: if Mix.env() == :dev, do: [:insecure], else: []
      6. Proper error handling for certificate validation failures
      """
    }
  end

  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.8,
      context_rules: %{
        http_libraries: [
          "HTTPoison",
          "Tesla",
          "hackney",
          "Req",
          "Finch",
          "Mint",
          "Gun",
          ":httpc"
        ],
        insecure_options: [
          "verify_none",
          "insecure",
          "verify: false",
          "verify_peer: false",
          "ssl: false"
        ],
        secure_options: [
          "verify_peer",
          "verify: true",
          "cacerts",
          "verify_fun",
          "depth",
          "crl_check"
        ],
        config_contexts: [
          "config",
          "Application.put_env",
          "System.put_env",
          "conn_opts",
          "adapter_opts",
          "client_options"
        ]
      },
      confidence_rules: %{
        base: 0.8,
        adjustments: %{
          verify_none_bonus: 0.2,
          hackney_insecure_bonus: 0.2,
          development_context_penalty: -0.7,
          test_context_penalty: -0.9,
          environment_check_penalty: -0.8,
          secure_option_penalty: -0.6
        }
      },
      ast_rules: %{
        node_type: "ssl_verification_analysis",
        ssl_analysis: %{
          check_ssl_options: true,
          ssl_option_keys: ["ssl", "ssl_options", "tls_options", "connect_options"],
          check_hackney_options: true,
          detect_environment_checks: true
        },
        library_analysis: %{
          check_http_clients: true,
          http_client_modules: ["HTTPoison", "Tesla", "Req", "Finch"],
          check_adapter_config: true,
          adapter_modules: ["Hackney", "Mint", "Gun"]
        },
        environment_analysis: %{
          detect_mix_env: true,
          development_indicators: ["dev", "test", "local"],
          check_conditional_config: true,
          environment_functions: ["Mix.env", "System.get_env"]
        }
      }
    }
  end
end
