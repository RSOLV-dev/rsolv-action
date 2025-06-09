defmodule RsolvApi.Security.Patterns.Cve do
  @moduledoc """
  Cross-language vulnerability patterns for detecting specific CVEs (Common Vulnerabilities and Exposures).
  
  CVEs are standardized identifiers for publicly known security vulnerabilities that can
  affect software regardless of programming language. This module contains patterns to detect
  specific high-profile CVEs that have broad impact across multiple languages and frameworks.
  
  These patterns focus on detecting vulnerable configurations, dependencies, or code patterns
  that indicate the presence of these well-known vulnerabilities.
  """
  
  alias RsolvApi.Security.Pattern
  
  @doc """
  Returns all CVE and critical vulnerability patterns.
  
  ## Examples
  
      iex> patterns = RsolvApi.Security.Patterns.Cve.all()
      iex> length(patterns)
      4
      iex> Enum.all?(patterns, &match?(%Pattern{}, &1))
      true
  """
  def all do
    [
      log4shell_detection(),
      spring4shell_detection(),
      weak_jwt_secret(),
      missing_security_event_logging()
    ]
  end
  
  @doc """
  Log4Shell Vulnerability (CVE-2021-44228) pattern.
  
  Detects potentially vulnerable Log4j versions.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Cve.log4shell_detection()
      iex> pattern.id
      "log4shell-detection"
      iex> pattern.severity
      :critical
  """
  def log4shell_detection do
    %Pattern{
      id: "log4shell-detection",
      name: "Log4Shell Vulnerability (CVE-2021-44228)",
      description: "Detects potentially vulnerable Log4j versions (CVE-2021-44228 - Log4Shell)",
      type: :cve,
      severity: :critical,
      languages: ["java", "kotlin", "groovy", "scala", "xml", "gradle", "maven"],
      regex: ~r/(log4j.*2\.(0|1[0-6])\.\d|log4j-core.*2\.(0|1[0-6])\.\d|<artifactId>log4j-core<\/artifactId>[\s\S]*?<version>2\.(0|1[0-6])\.\d<\/version>)/i,
      default_tier: :public,
      cwe_id: "CWE-502",
      owasp_category: "A06:2021",
      recommendation: "Update Log4j to version 2.17.0 or later to patch Log4Shell vulnerability",
      test_cases: %{
        vulnerable: [
          ~S|implementation "org.apache.logging.log4j:log4j-core:2.14.1"|,
          ~S|<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-core</artifactId>
  <version>2.15.0</version>
</dependency>|
        ],
        safe: [
          ~S|implementation "org.apache.logging.log4j:log4j-core:2.17.1"|,
          ~S|<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-core</artifactId>
  <version>2.20.0</version>
</dependency>|
        ]
      }
    }
  end
  
  @doc """
  Spring4Shell Vulnerability (CVE-2022-22965) pattern.
  
  Detects potentially vulnerable Spring Framework versions.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Cve.spring4shell_detection()
      iex> vulnerable = ~S|implementation "org.springframework:spring-webmvc:5.3.17"|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def spring4shell_detection do
    %Pattern{
      id: "spring4shell-detection",
      name: "Spring4Shell Vulnerability (CVE-2022-22965)",
      description: "Detects potentially vulnerable Spring Framework versions (CVE-2022-22965 - Spring4Shell)",
      type: :cve,
      severity: :critical,
      languages: ["java", "kotlin", "xml", "gradle", "maven"],
      frameworks: ["spring"],
      regex: ~r/(spring-webmvc|spring-boot-starter-web)[\s\S]*?(?:5\.[0-2]\.\d{1,2}|5\.3\.(?:[0-9]|1[0-7])(?:\D|$))/i,
      default_tier: :public,
      cwe_id: "CWE-94",
      owasp_category: "A06:2021",
      recommendation: "Update Spring Framework to 5.3.18+ or 5.2.20+ to patch Spring4Shell vulnerability",
      test_cases: %{
        vulnerable: [
          ~S|implementation "org.springframework:spring-webmvc:5.3.17"|,
          ~S|<dependency>
  <groupId>org.springframework</groupId>
  <artifactId>spring-webmvc</artifactId>
  <version>5.3.16</version>
</dependency>|
        ],
        safe: [
          ~S|implementation "org.springframework:spring-webmvc:5.3.20"|,
          ~S|implementation "org.springframework:spring-webmvc:6.0.0"|
        ]
      }
    }
  end
  
  @doc """
  Weak JWT Secret Detection pattern.
  
  Detects weak JWT secrets that are too short or predictable.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Cve.weak_jwt_secret()
      iex> vulnerable = ~S|jwt.sign(payload, "secret")|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def weak_jwt_secret do
    %Pattern{
      id: "weak-jwt-secret",
      name: "Weak JWT Secret Detection",
      description: "Detects weak JWT secrets that are too short or predictable",
      type: :authentication,
      severity: :high,
      languages: ["javascript", "typescript"],
      regex: ~r/jwt\.sign\([^,]+,\s*["']([^"']{1,16})["']/i,
      default_tier: :public,
      cwe_id: "CWE-326",
      owasp_category: "A07:2021",
      recommendation: "Use a strong, randomly generated secret of at least 256 bits (32 characters)",
      test_cases: %{
        vulnerable: [
          ~S|jwt.sign(payload, "secret")|,
          ~S|jwt.sign(userData, "mySecretKey")|,
          ~S|jwt.sign(token, "1234567890")|
        ],
        safe: [
          ~S|jwt.sign(payload, crypto.randomBytes(32).toString("hex"))|,
          ~S|jwt.sign(payload, process.env.JWT_SECRET)|,
          ~S|jwt.sign(payload, "a7f8d9e2b4c6a1e3f5d7b9c1e3a5c7d9e2b4f6a8c0e2d4f6a8b0c2d4e6f8")|
        ]
      }
    }
  end
  
  @doc """
  Missing Security Event Logging pattern.
  
  Detects security-critical operations without proper logging.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Cve.missing_security_event_logging()
      iex> vulnerable = "function login(username, password) { if (checkCredentials(username, password)) return createSession(username); }"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def missing_security_event_logging do
    %Pattern{
      id: "missing-security-event-logging",
      name: "Missing Security Event Logging",
      description: "Detects security-critical operations without proper logging",
      type: :logging,
      severity: :medium,
      languages: [], # Applies to all languages
      regex: ~r/(?:def|function)\s+(?:login|authenticate|authorize|(?:process_)?payment|transfer|delete)\b[\s\S]{0,200}(?:return|end|\})(?![\s\S]{0,200}\b(?:log|audit|track|record|logger)\b)/i,
      default_tier: :public,
      cwe_id: "CWE-778",
      owasp_category: "A09:2021",
      recommendation: "Add comprehensive logging for all security-critical operations including authentication, authorization, and sensitive data access",
      test_cases: %{
        vulnerable: [
          ~S|function login(username, password) { 
  if (checkCredentials(username, password)) 
    return createSession(username); 
}|,
          ~S|def process_payment(amount, card_number):
    charge_card(card_number, amount)
    return "Success"|
        ],
        safe: [
          ~S|function login(username, password) { 
  const result = checkCredentials(username, password); 
  logger.info("Login attempt", { username, success: result }); 
  return result ? createSession(username) : false; 
}|,
          ~S|def process_payment(amount, card_number):
    audit_log.info(f"Payment attempt for amount: {amount}")
    result = charge_card(card_number, amount)
    audit_log.info(f"Payment result: {result}")
    return result|
        ]
      }
    }
  end
end