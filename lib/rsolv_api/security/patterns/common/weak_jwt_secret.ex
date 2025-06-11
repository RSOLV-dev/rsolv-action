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
      default_tier: :public,  # This is a critical issue, available in public tier
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
  def applies_to_file?(file_path, content \\ nil) do
    # This pattern applies to ALL files since JWT can be used anywhere
    true
  end
end