defmodule Rsolv.Security.Patterns.Java.TrustAllCerts do
  @moduledoc """
  Trust All Certificates pattern for Java code.
  
  Detects implementations of TrustManager and HostnameVerifier that accept all certificates
  without proper validation. These "trust all" implementations disable SSL/TLS certificate
  verification, making applications vulnerable to Man-in-the-Middle (MitM) attacks.
  
  ## Vulnerability Details
  
  Trust all certificates vulnerabilities occur when applications bypass SSL/TLS certificate
  validation by implementing empty or permissive TrustManager and HostnameVerifier classes.
  This removes the cryptographic protections that certificates provide, allowing attackers
  to intercept and modify network communications.
  
  Common vulnerable patterns:
  - Empty checkClientTrusted() and checkServerTrusted() methods in X509TrustManager
  - HostnameVerifier that always returns true
  - SSLContext initialized with permissive TrustManager arrays
  - Disabled certificate validation in HTTP clients
  - Custom TrustManager implementations that don't perform validation
  
  ### Attack Examples
  
  ```java
  // Vulnerable code - TrustManager that accepts all certificates
  TrustManager[] trustAllCerts = new TrustManager[] {
      new X509TrustManager() {
          public void checkClientTrusted(X509Certificate[] chain, String authType) {}
          public void checkServerTrusted(X509Certificate[] chain, String authType) {}
          public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
      }
  };
  
  // Vulnerable code - HostnameVerifier that accepts all hostnames
  HostnameVerifier allHostsValid = new HostnameVerifier() {
      public boolean verify(String hostname, SSLSession session) { return true; }
  };
  ```
  
  ## References
  
  - CWE-295: Improper Certificate Validation
  - OWASP A07:2021 - Identification and Authentication Failures
  - Android Security Advisory: Unsafe X509TrustManager implementations
  - CVE-2020-26234: MiTM vulnerabilities in applications with insecure TrustManager
  """
  
  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern
  
  @doc """
  Pattern detects trust all certificates implementations in Java code.
  
  Identifies implementations that bypass SSL/TLS certificate validation, including
  empty TrustManager methods and permissive HostnameVerifier implementations.
  
  ## Examples
  
      iex> pattern = Rsolv.Security.Patterns.Java.TrustAllCerts.pattern()
      iex> pattern.id
      "java-trust-all-certs"
      
      iex> pattern = Rsolv.Security.Patterns.Java.TrustAllCerts.pattern()
      iex> pattern.severity
      :critical
      
      iex> pattern = Rsolv.Security.Patterns.Java.TrustAllCerts.pattern()
      iex> vulnerable = "public void checkClientTrusted(X509Certificate[] chain, String authType) {}"
      iex> Enum.any?(pattern.regex, fn r -> Regex.match?(r, vulnerable) end)
      true
      
      iex> pattern = Rsolv.Security.Patterns.Java.TrustAllCerts.pattern()
      iex> safe = "public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException { validateCertificateChain(chain); }"
      iex> Enum.any?(pattern.regex, fn r -> Regex.match?(r, safe) end)
      false
  """
  @impl true
  def pattern do
    %Pattern{
      id: "java-trust-all-certs",
      name: "Trust All Certificates",
      description: "TrustManager or HostnameVerifier implementations that bypass certificate validation",
      type: :authentication,
      severity: :critical,
      languages: ["java"],
      regex: [
        # Empty checkClientTrusted implementation - exclude commented lines and strings
        ~r/^(?!.*\/\/)(?!.*["']).*checkClientTrusted\s*\(\s*X509Certificate\[\]\s*\w+\s*,\s*String\s*\w+\s*\)\s*(?:throws\s+\w+\s*)?\{\s*(?:\/\*[^}]*\*\/\s*|\/\/[^}]*|\s*return\s*;\s*|\s*)\s*\}/m,
        # Empty checkServerTrusted implementation - exclude commented lines and strings
        ~r/^(?!.*\/\/)(?!.*["']).*checkServerTrusted\s*\(\s*X509Certificate\[\]\s*\w+\s*,\s*String\s*\w+\s*\)\s*(?:throws\s+\w+\s*)?\{\s*(?:\/\*[^}]*\*\/\s*|\/\/[^}]*|\s*return\s*;\s*|\s*)\s*\}/m,
        # HostnameVerifier that returns true - exclude commented lines and strings
        ~r/^(?!.*\/\/)(?!.*["']).*verify\s*\(\s*String\s*\w+\s*,\s*SSLSession\s*\w+\s*\)\s*\{\s*(?:\/\*[^}]*\*\/\s*|\/\/[^}]*|\s*)\s*return\s+true\s*;\s*\}/m,
        # TrustManager array with empty implementations - exclude commented lines
        ~r/^(?!.*\/\/).*TrustManager\[\]\s*\w+\s*=.*new\s+X509TrustManager\(\)\s*\{[^}]*checkClientTrusted[^}]*\{\s*\}/m,
        # SSL context initialization with trust all - exclude commented lines
        ~r/^(?!.*\/\/).*\.init\s*\(\s*null\s*,\s*(?:trustAllCerts|trustAll\w*|.*TrustManager\[\].*)\s*,.*\)/m,
        # HostnameVerifier lambda or assignment that returns true - exclude commented lines
        ~r/^(?!.*\/\/).*HostnameVerifier.*=.*\(\s*\w+\s*,\s*\w+\s*\)\s*->\s*true/m,
        # setDefaultHostnameVerifier and setDefaultSSLSocketFactory - exclude commented lines
        ~r/^(?!.*\/\/).*setDefault(?:HostnameVerifier|SSLSocketFactory)\s*\([^)]*\)/m
      ],
      cwe_id: "CWE-295",
      owasp_category: "A07:2021",
      recommendation: "Implement proper certificate validation using default TrustManager or custom validation logic",
      test_cases: %{
        vulnerable: [
          ~S|public void checkClientTrusted(X509Certificate[] chain, String authType) {}|,
          ~S|public void checkServerTrusted(X509Certificate[] chain, String authType) {}|,
          ~S|public boolean verify(String hostname, SSLSession session) { return true; }|,
          ~S|TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() { public void checkClientTrusted(X509Certificate[] chain, String authType) {} } };|,
          ~S|HostnameVerifier allHostsValid = (hostname, session) -> true;|
        ],
        safe: [
          ~S|public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException { validateCertificateChain(chain); }|,
          ~S|public boolean verify(String hostname, SSLSession session) { return validateHostname(hostname, session); }|,
          ~S|// TrustManager[] trustAllCerts = new TrustManager[] { /* commented out */ };|,
          ~S|TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());|,
          ~S|SSLContext sslContext = SSLContext.getDefault();|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Trust all certificates vulnerabilities occur when applications disable SSL/TLS certificate
      validation by implementing permissive TrustManager and HostnameVerifier classes. This removes
      the cryptographic protections that certificates provide, making applications vulnerable to
      Man-in-the-Middle (MitM) attacks where attackers can intercept and modify network communications.
      
      These vulnerabilities typically manifest through:
      - Empty checkClientTrusted() and checkServerTrusted() methods that don't perform validation
      - HostnameVerifier implementations that always return true regardless of hostname
      - SSLContext configurations that use custom TrustManager arrays without validation
      - HTTP clients configured to ignore certificate errors
      - Development code that disables certificate checks accidentally reaching production
      
      The vulnerability is particularly dangerous because:
      - It completely bypasses the PKI (Public Key Infrastructure) security model
      - Attackers can use self-signed certificates to impersonate legitimate servers
      - Network traffic becomes vulnerable to interception and modification
      - Users have no indication that their connections are insecure
      - Compliance frameworks explicitly prohibit disabling certificate validation
      
      Historical context:
      - Featured in OWASP Top 10 2021 under A07 (Identification and Authentication Failures)
      - Common in mobile applications leading to Google Play Store warnings
      - Frequently found in enterprise applications during penetration testing
      - Often introduced during development and accidentally left in production
      - Regulatory compliance violations in industries requiring secure communications
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-295",
          title: "Improper Certificate Validation",
          url: "https://cwe.mitre.org/data/definitions/295.html"
        },
        %{
          type: :owasp,
          id: "A07:2021",
          title: "OWASP Top 10 2021 - A07 Identification and Authentication Failures", 
          url: "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
        },
        %{
          type: :research,
          id: "android_unsafe_trustmanager",
          title: "Android Security: Unsafe X509TrustManager implementations",
          url: "https://developer.android.com/privacy-and-security/risks/unsafe-trustmanager"
        },
        %{
          type: :research,
          id: "owasp_certificate_pinning",
          title: "OWASP Certificate and Public Key Pinning",
          url: "https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning"
        },
        %{
          type: :research,
          id: "tls_certificate_validation_guide",
          title: "Transport Layer Security Certificate Validation Guide",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"
        }
      ],
      attack_vectors: [
        "Man-in-the-Middle (MitM): Attacker intercepts network traffic using rogue access points or network positioning",
        "Certificate substitution: Attacker presents self-signed or fraudulent certificates that are accepted",
        "DNS spoofing combined with certificate bypass: Redirecting traffic to attacker-controlled servers",
        "Network infrastructure compromise: Leveraging compromised routers or switches to intercept traffic",
        "Public Wi-Fi exploitation: Using open networks to position between client and legitimate servers",
        "BGP hijacking with certificate bypass: Redirecting network routes to attacker infrastructure",
        "Domain validation bypass: Using certificates for similar but malicious domains that are accepted"
      ],
      real_world_impact: [
        "Financial data interception: Banking and payment applications vulnerable to credential theft",
        "Corporate espionage: Business communications and trade secrets intercepted by competitors",
        "Personal data exposure: User credentials, private messages, and sensitive documents compromised",
        "Government and military communications: Classified information potentially intercepted",
        "Healthcare data breaches: Medical records and patient information exposed during transmission",
        "E-commerce fraud: Shopping and payment details stolen during online transactions",
        "API security bypass: Backend services vulnerable to data exfiltration and manipulation"
      ],
      cve_examples: [
        %{
          id: "CVE-2020-26234",
          description: "Multiple applications use insecure TrustManager implementations allowing MitM attacks",
          severity: "high",
          cvss: 7.4,
          note: "Affects applications that trust all certificates, enabling traffic interception"
        },
        %{
          id: "CVE-2019-16303",
          description: "JHipster Generator creates applications with disabled certificate validation",
          severity: "medium", 
          cvss: 6.5,
          note: "Generated applications contain TrustManager that accepts all certificates"
        },
        %{
          id: "CVE-2018-1000613",
          description: "Jenkins plugins with insecure TrustManager implementations",
          severity: "medium",
          cvss: 5.9,
          note: "Multiple Jenkins plugins bypass certificate validation, allowing MitM attacks"
        }
      ],
      detection_notes: """
      This pattern detects certificate validation bypass by identifying:
      
      1. Empty TrustManager method implementations with minimal or no validation logic
      2. HostnameVerifier methods that unconditionally return true
      3. SSLContext initialization patterns that use permissive TrustManager arrays
      4. Lambda expressions and method references that bypass hostname verification
      5. Configuration patterns that disable certificate validation
      
      The pattern uses negative lookahead to exclude commented lines and focuses on:
      - Method signatures for checkClientTrusted and checkServerTrusted
      - Empty method bodies or bodies containing only comments/return statements
      - HostnameVerifier verify methods that return true without validation
      - SSLContext and HttpsURLConnection configuration patterns
      - TrustManager array declarations with empty implementations
      
      Key detection criteria:
      - Looks for method signatures with empty or minimal implementations
      - Excludes properly commented development code
      - Covers both anonymous inner classes and lambda expressions
      - Identifies both TrustManager and HostnameVerifier bypass patterns
      """,
      safe_alternatives: [
        "Use default TrustManager from TrustManagerFactory.getDefaultAlgorithm()",
        "Implement proper certificate validation logic in custom TrustManager implementations",
        "Use certificate pinning for enhanced security in high-risk applications",
        "Validate certificate chains, expiration dates, and certificate authorities",
        "Implement proper hostname verification in custom HostnameVerifier implementations",
        "Use SSLContext.getDefault() for standard certificate validation",
        "Configure HTTP clients to use proper certificate validation",
        "Implement certificate transparency validation for additional security"
      ],
      additional_context: %{
        common_mistakes: [
          "Disabling certificate validation temporarily during development and forgetting to re-enable",
          "Believing that internal networks don't require certificate validation",
          "Using trust all certificates for testing and accidentally deploying to production",
          "Implementing custom TrustManager without understanding proper validation requirements",
          "Assuming that HTTPS automatically provides security without proper certificate validation",
          "Copying code examples that disable validation without understanding the security implications",
          "Not understanding the difference between certificate validation and encryption"
        ],
        secure_patterns: [
          "Always use default certificate validation unless specific requirements dictate otherwise",
          "Implement certificate pinning for mobile applications and high-security environments",
          "Use proper error handling that fails securely when certificate validation fails",
          "Regularly update certificate stores and validate certificate chain integrity",
          "Implement proper logging and monitoring for certificate validation failures",
          "Use configuration management to ensure certificate validation is enabled in production",
          "Regular security reviews of SSL/TLS configuration and certificate handling code",
          "Automated testing to verify certificate validation is working correctly"
        ],
        java_specific_considerations: [
          "Default TrustManagerFactory provides secure certificate validation for most use cases",
          "X509TrustManager checkClientTrusted and checkServerTrusted should throw CertificateException for invalid certificates",
          "HostnameVerifier verify method should return false for invalid or mismatched hostnames",
          "SSLContext should be initialized with proper TrustManager arrays from TrustManagerFactory",
          "HttpsURLConnection uses default certificate validation unless explicitly overridden",
          "Custom TrustManager implementations should delegate to default implementation when possible"
        ],
        compliance_impact: [
          "PCI DSS: Credit card processing requires proper certificate validation for secure communications",
          "HIPAA: Healthcare applications must use proper certificate validation for patient data protection",
          "SOX: Financial reporting systems require secure communications with proper certificate validation",
          "GDPR: Personal data transmission must be properly secured including certificate validation",
          "ISO 27001: Information security standards mandate proper certificate validation procedures",
          "NIST Cybersecurity Framework: Requires proper implementation of cryptographic controls"
        ]
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual certificate validation bypass
  vulnerabilities and acceptable uses such as development testing or specific configurations.
  
  ## Examples
  
      iex> enhancement = Rsolv.Security.Patterns.Java.TrustAllCerts.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Java.TrustAllCerts.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
      
      iex> enhancement = Rsolv.Security.Patterns.Java.TrustAllCerts.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "MethodDeclaration"
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "MethodDeclaration",
        trust_analysis: %{
          check_trust_manager: true,
          trust_manager_methods: ["checkClientTrusted", "checkServerTrusted", "getAcceptedIssuers"],
          check_empty_implementation: true,
          check_method_body: true,
          empty_body_indicators: ["return;", "// TODO", "/* TODO */", "throw new UnsupportedOperationException"]
        },
        certificate_analysis: %{
          check_certificate_validation: true,
          validation_methods: ["validateCertificateChain", "checkValidity", "verify"],
          bypass_patterns: ["return true", "return;", "{}", "{ }", "{ /* empty */ }"],
          certificate_exception_handling: true
        },
        hostname_analysis: %{
          check_hostname_verification: true,
          verifier_methods: ["verify"],
          bypass_indicators: ["return true", "true", "-> true"],
          hostname_validation_methods: ["validateHostname", "checkHostname", "verifyHostname"]
        },
        ssl_analysis: %{
          check_ssl_context: true,
          ssl_methods: ["init", "setDefaultSSLSocketFactory", "setDefaultHostnameVerifier"],
          insecure_configurations: ["trustAllCerts", "trustAll", "allHostsValid"],
          secure_context_patterns: ["SSLContext.getDefault", "TrustManagerFactory.getInstance"]
        }
      },
      context_rules: %{
        check_certificate_usage: true,
        secure_trust_patterns: [
          "TrustManagerFactory.getInstance",
          "SSLContext.getDefault",
          "CertificateFactory.getInstance",
          "validateCertificateChain",
          "checkValidity"
        ],
        insecure_trust_indicators: [
          "trust_all_certificates",
          "disable_ssl_verification", 
          "accept_all_certificates",
          "ignore_ssl_errors",
          "bypass_certificate_validation"
        ],
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/example/, ~r/demo/, ~r/sample/],
        development_indicators: [
          "development", "dev", "test", "demo", "example", "sample", "local", "localhost"
        ],
        production_contexts: [
          "production", "prod", "live", "release", "deployed", "enterprise", "commercial"
        ]
      },
      confidence_rules: %{
        base: 0.7,
        adjustments: %{
          "has_proper_validation" => -0.8,
          "empty_trust_implementation" => 0.3,
          "returns_true_always" => 0.2,
          "uses_trust_all_pattern" => 0.2,
          "has_certificate_exception" => -0.4,
          "in_test_code" => -0.5,
          "for_development_only" => -0.4,
          "has_todo_comments" => -0.3,
          "is_commented_out" => -0.9,
          "in_production_context" => 0.3,
          "has_security_comments" => -0.2
        }
      },
      min_confidence: 0.8
    }
  end
end
