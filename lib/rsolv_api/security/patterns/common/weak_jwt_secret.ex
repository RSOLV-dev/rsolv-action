defmodule RsolvApi.Security.Patterns.Common.WeakJwtSecret do
  @moduledoc """
  Weak JWT Secret Detection - Cross-Language Pattern
  
  Detects hardcoded or weak JWT secrets across all languages.
  JWT vulnerabilities are language-agnostic since JWT is a standard
  that can be used in any programming language.
  
  Vulnerable patterns:
  - Hardcoded secrets: jwt.sign(data, "secret123")
  - Weak secrets: SECRET_KEY = "password"
  - Common defaults: process.env.JWT_SECRET || "changeme"
  
  Safe patterns:
  - Strong secrets from environment: process.env.JWT_SECRET (with proper validation)
  - Cryptographically secure secrets: crypto.randomBytes(64).toString('hex')
  - Key rotation mechanisms
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  
  @doc """
  Returns the pattern definition for weak JWT secrets.
  
  This pattern applies to ALL languages since JWT usage is cross-language.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Common.WeakJwtSecret.pattern()
      iex> pattern.languages
      ["all"]
      iex> pattern.type
      :jwt
  """
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "weak-jwt-secret",
      name: "Weak or Hardcoded JWT Secret",
      description: "Detects weak, hardcoded, or default JWT secrets that compromise token security",
      type: :jwt,
      severity: :critical,
      languages: ["all"],  # Applies to all languages
      frameworks: nil,     # Framework-agnostic
      regex: [
        # Hardcoded secrets in JWT operations
        ~r/jwt\.(?:sign|verify)\s*\([^,]+,\s*["'](?:secret|password|123|admin|default|changeme)/i,
        # Weak secret assignments
        ~r/(?:JWT_SECRET|SECRET_KEY|TOKEN_SECRET)\s*[:=]\s*["'](?:secret|password|123|admin|default|changeme)/i,
        # Default fallbacks to weak values
        ~r/(?:process\.env\.|ENV\\\[|getenv).*?\|\|?\s*["'](?:secret|password|123|admin|default|changeme)/i,
        # Short secrets (less than 16 chars)
        ~r/(?:jwt|token).*?secret.*?[:=]\s*["'][^"']{1,15}["']/i
      ],
      cwe_id: "CWE-798",
      owasp_category: "A02:2021",
      recommendation: "Use strong, randomly generated secrets of at least 256 bits. Store secrets in secure environment variables or key management systems. Implement key rotation.",
      test_cases: %{
        vulnerable: [
          ~S|jwt.sign(payload, "secret123")|,
          ~S|const JWT_SECRET = "password"|,
          ~S{SECRET_KEY = ENV['JWT_SECRET'] || "changeme"},
          ~S{$token = JWT::encode($data, 'admin', 'HS256');},
          ~S|jwt_secret: str = "12345"|,
          ~S|JWT.encode(payload, "short", algorithm: "HS256")|
        ],
        safe: [
          ~S|jwt.sign(payload, process.env.JWT_SECRET)|,
          ~S{const JWT_SECRET = crypto.randomBytes(64).toString('hex')},
          ~S|SECRET_KEY = Rails.application.credentials.jwt_secret|,
          ~S{jwt_secret = os.environ['JWT_SECRET']  # With proper validation elsewhere},
          ~S|JWT.encode(payload, fetch_secret_from_vault(), algorithm: "HS256")|
        ]
      }
    }
  end
  
  @doc """
  Override to handle multi-language files and embedded JWT usage.
  """
  def applies_to_file?(_file_path, _content \\ nil) do
    # This pattern applies to ALL files since JWT can be used anywhere
    true
  end
  
  @doc """
  Comprehensive vulnerability metadata for weak JWT secrets.
  
  This metadata documents the critical security implications of using weak,
  hardcoded, or default JWT secrets across all programming languages.
  """
  def vulnerability_metadata do
    %{
      description: """
      JSON Web Tokens (JWT) rely on cryptographic signatures to ensure authenticity 
      and integrity. When weak, hardcoded, or default secrets are used to sign JWTs, 
      attackers can forge valid tokens, completely bypassing authentication and 
      authorization mechanisms. This vulnerability is particularly severe because JWTs 
      are often used for stateless authentication across distributed systems.
      
      The vulnerability manifests in several ways:
      1. Hardcoded secrets in source code (e.g., jwt.sign(data, "secret123"))
      2. Default fallback values (e.g., process.env.JWT_SECRET || "changeme")
      3. Weak secrets that can be brute-forced (e.g., common words, short strings)
      4. Secrets stored in public repositories or client-side code
      
      Modern JWT cracking tools can test millions of weak secrets per second, making
      short or predictable secrets completely insecure. Once an attacker discovers
      the secret, they can forge tokens with arbitrary claims, impersonate any user,
      escalate privileges, and maintain persistent access to the system.
      
      This vulnerability is language-agnostic and affects any system using JWT,
      regardless of the programming language or framework.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-798",
          title: "Use of Hard-coded Credentials",
          url: "https://cwe.mitre.org/data/definitions/798.html"
        },
        %{
          type: :owasp,
          id: "A02:2021",
          title: "OWASP Top 10 2021 - A02 Cryptographic Failures",
          url: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
        },
        %{
          type: :owasp,
          id: "jwt_cheat_sheet",
          title: "JSON Web Token for Java Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"
        },
        %{
          type: :research,
          id: "portswigger_jwt",
          title: "JWT attacks - PortSwigger Web Security Academy",
          url: "https://portswigger.net/web-security/jwt"
        },
        %{
          type: :research,
          id: "pentesterlab_jwt",
          title: "The Ultimate Guide to JWT Vulnerabilities and Attacks",
          url: "https://pentesterlab.com/blog/jwt-vulnerabilities-attacks-guide"
        }
      ],
      attack_vectors: [
        "Brute-force attack: Testing common secrets like 'secret', 'password', '123456'",
        "Dictionary attack: Using wordlists of common JWT secrets found in breaches",
        "Source code analysis: Finding hardcoded secrets in public repositories",
        "Configuration file exposure: Accessing .env files or config files with weak secrets",
        "Default credential exploitation: Using known default secrets from frameworks",
        "Rainbow table attacks: Pre-computed hashes for common JWT secrets",
        "JWT tool automation: Using jwt_tool or similar to crack weak secrets",
        "Algorithm downgrade: Combining with 'none' algorithm attacks"
      ],
      real_world_impact: [
        "Complete authentication bypass allowing impersonation of any user",
        "Privilege escalation to admin or system-level access",
        "Data breach through unauthorized API access",
        "Account takeover at scale across all users",
        "Persistent backdoor access via forged long-lived tokens",
        "Compliance violations (GDPR, HIPAA, PCI-DSS)",
        "Financial fraud through forged payment authorization tokens",
        "Supply chain attacks by compromising API tokens"
      ],
      cve_examples: [
        %{
          id: "CVE-2022-23529",
          description: "JWT Secret Poisoning in node-jsonwebtoken allowing authentication bypass",
          severity: "critical",
          cvss: 9.8,
          note: "Allowed attackers to bypass authentication by exploiting weak secret handling"
        },
        %{
          id: "CVE-2018-0114",
          description: "PyJWT library vulnerability allowing authentication bypass via weak secrets",
          severity: "high",
          cvss: 7.5,
          note: "Popular Python JWT library vulnerable to weak secret exploitation"
        },
        %{
          id: "CVE-2023-46943",
          description: "Weak token secret vulnerability in multiple JWT implementations",
          severity: "high",
          cvss: 8.1,
          note: "Widespread vulnerability affecting multiple JWT libraries"
        },
        %{
          id: "GHSA-gvcr-g265-j827",
          description: "YourSpotify hardcoded JWT secret allowing admin impersonation",
          severity: "critical",
          cvss: 9.8,
          note: "Hardcoded JWT secret 'ILoveSpotify' allowed complete authentication bypass"
        }
      ],
      detection_notes: """
      This pattern detects weak JWT secrets through multiple regex patterns:
      
      1. Direct hardcoded secrets in JWT operations (jwt.sign with literal strings)
      2. Weak secret assignments to common variable names (JWT_SECRET, SECRET_KEY)
      3. Default fallback patterns using OR operators (|| "changeme")
      4. Short secrets (less than 16 characters) assigned to JWT-related variables
      
      The pattern is language-agnostic and searches for common JWT library usage
      patterns across all major programming languages. It focuses on detecting
      obviously weak secrets that violate security best practices.
      """,
      safe_alternatives: [
        "Generate cryptographically secure random secrets of at least 256 bits (32 bytes)",
        "Use environment variables or secure key management systems (AWS KMS, HashiCorp Vault)",
        "Implement key rotation mechanisms to regularly update JWT secrets",
        "Use asymmetric algorithms (RS256, ES256) instead of symmetric (HS256)",
        "Store secrets in secure secret management services, never in code",
        "Implement proper secret validation on application startup",
        "Use different secrets for different environments (dev, staging, prod)",
        "Monitor for exposed secrets in version control and rotate immediately if found"
      ],
      additional_context: %{
        common_mistakes: [
          "Using dictionary words or common phrases as secrets",
          "Reusing the same secret across multiple applications or environments",
          "Storing secrets in version control, even in private repositories",
          "Using short secrets that can be brute-forced quickly",
          "Hardcoding fallback secrets for 'development' that leak to production",
          "Not rotating secrets after employee departures or security incidents",
          "Using the framework name or application name as the secret"
        ],
        secure_patterns: [
          "Generate secrets using crypto.randomBytes(32) or equivalent",
          "Enforce minimum secret length of 32 characters in configuration",
          "Use key derivation functions if secrets must be derived from passwords",
          "Implement secret rotation workflows with zero-downtime deployment",
          "Use separate signing and verification keys where possible",
          "Monitor JWT usage patterns for anomalies indicating compromised secrets",
          "Implement JWT revocation mechanisms for emergency response"
        ],
        framework_specific_risks: %{
          nodejs: [
            "jsonwebtoken library defaults allow weak secrets without warning",
            "Express sessions often misconfigured with weak JWT secrets",
            "Many tutorials show hardcoded secrets in examples"
          ],
          python: [
            "PyJWT accepts any string as secret without validation",
            "Flask-JWT often configured with weak secrets in tutorials",
            "Django REST framework JWT settings often expose weak defaults"
          ],
          java: [
            "Spring Security JWT often configured with property files containing weak secrets",
            "JJWT library examples often show hardcoded secrets",
            "Microservices often share weak secrets across services"
          ],
          php: [
            "Firebase JWT-PHP commonly used with weak secrets",
            "Laravel Passport default configuration vulnerable to weak secrets",
            "Many PHP frameworks use weak defaults for backward compatibility"
          ]
        }
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual weak JWT secrets and
  legitimate uses of JWT libraries with proper secret management.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Common.WeakJwtSecret.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Common.WeakJwtSecret.ast_enhancement()
      iex> enhancement.min_confidence
      0.9
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        # JWT operations across languages
        patterns: [
          # JavaScript/TypeScript
          %{language: "javascript", callee: ["jwt.sign", "jwt.verify", "jsonwebtoken.sign"]},
          # Python
          %{language: "python", callee: ["jwt.encode", "jwt.decode", "PyJWT.encode"]},
          # Java
          %{language: "java", callee: ["Jwts.builder", "JWT.create", "JWTCreator.sign"]},
          # PHP
          %{language: "php", callee: ["JWT::encode", "Firebase\\JWT\\JWT::encode"]},
          # Ruby
          %{language: "ruby", callee: ["JWT.encode", "JWT.decode"]},
          # C#
          %{language: "csharp", callee: ["JwtSecurityTokenHandler.WriteToken"]}
        ],
        # Check for weak secret patterns
        weak_secret_indicators: [
          "secret", "password", "123", "admin", "default", "changeme",
          "test", "demo", "example", "sample", "temp", "todo"
        ]
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/examples/, ~r/docs/],
        exclude_if_contains: ["// not for production", "# development only"],
        high_risk_indicators: [
          "production", "prod", "live", "release",
          "authentication", "auth", "security"
        ]
      },
      confidence_rules: %{
        base: 0.8,  # High base - weak secrets are critical
        adjustments: %{
          "hardcoded_literal" => 0.2,      # Direct string literals
          "weak_secret_pattern" => 0.15,   # Contains weak patterns
          "short_secret" => 0.2,           # Less than 16 chars
          "in_production_code" => 0.1,     # Production indicators
          "has_fallback" => 0.15,          # OR operator fallbacks
          "environment_variable" => -0.7,  # Proper env var usage
          "from_key_store" => -0.8,        # Key management system
          "strong_secret_pattern" => -0.6  # Looks cryptographically strong
        }
      },
      min_confidence: 0.9  # High threshold - only report very likely issues
    }
  end
end
