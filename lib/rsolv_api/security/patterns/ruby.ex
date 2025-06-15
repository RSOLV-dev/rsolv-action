defmodule RsolvApi.Security.Patterns.Ruby do
  @moduledoc """
  Ruby security patterns for detecting vulnerabilities.
  
  This module contains 20 security patterns specifically designed for Ruby
  code. Each pattern includes detection rules, test cases, and educational
  documentation.
  """
  
  alias RsolvApi.Security.Pattern
  alias RsolvApi.Security.Patterns.Ruby.MissingAuthentication
  alias RsolvApi.Security.Patterns.Ruby.MassAssignment
  alias RsolvApi.Security.Patterns.Ruby.HardcodedSecrets
  alias RsolvApi.Security.Patterns.Ruby.SqlInjectionInterpolation
  alias RsolvApi.Security.Patterns.Ruby.CommandInjection
  alias RsolvApi.Security.Patterns.Ruby.XpathInjection
  alias RsolvApi.Security.Patterns.Ruby.LdapInjection
  alias RsolvApi.Security.Patterns.Ruby.WeakRandom
  alias RsolvApi.Security.Patterns.Ruby.DebugModeEnabled
  alias RsolvApi.Security.Patterns.Ruby.EvalUsage
  alias RsolvApi.Security.Patterns.Ruby.WeakPasswordStorage
  alias RsolvApi.Security.Patterns.Ruby.UnsafeDeserializationMarshal
  alias RsolvApi.Security.Patterns.Ruby.UnsafeYaml
  alias RsolvApi.Security.Patterns.Ruby.InsufficientLogging
  alias RsolvApi.Security.Patterns.Ruby.SsrfOpenUri
  alias RsolvApi.Security.Patterns.Ruby.XssErbRaw
  alias RsolvApi.Security.Patterns.Ruby.PathTraversal
  alias RsolvApi.Security.Patterns.Ruby.OpenRedirect
  alias RsolvApi.Security.Patterns.Ruby.InsecureCookie
  
  @doc """
  Returns all Ruby security patterns.
  
  ## Examples
  
      iex> patterns = RsolvApi.Security.Patterns.Ruby.all()
      iex> length(patterns)
      20
      iex> Enum.all?(patterns, &match?(%RsolvApi.Security.Pattern{}, &1))
      true
  """
  def all do
    [
      missing_authentication(),
      mass_assignment(),
      weak_crypto_md5(),
      hardcoded_secrets(),
      sql_injection_interpolation(),
      command_injection(),
      xpath_injection(),
      ldap_injection(),
      weak_random(),
      debug_mode_enabled(),
      eval_usage(),
      weak_password_storage(),
      unsafe_deserialization_marshal(),
      unsafe_yaml(),
      insufficient_logging(),
      ssrf_open_uri(),
      xss_erb_raw(),
      path_traversal(),
      open_redirect(),
      insecure_cookie()
    ]
  end
  
  @doc """
  Missing Authentication in Rails Controller pattern.
  
  Detects Rails controllers without authentication filters.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.missing_authentication()
      iex> pattern.id
      "ruby-broken-access-control-missing-auth"
      iex> pattern.severity
      :high
  """
  defdelegate missing_authentication(), to: MissingAuthentication, as: :pattern
  
  @doc """
  Mass Assignment Vulnerability pattern.
  
  Detects unfiltered params in model operations.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.mass_assignment()
      iex> pattern.type
      :mass_assignment
  """
  defdelegate mass_assignment(), to: MassAssignment, as: :pattern
  
  @doc """
  Hardcoded Secrets pattern.
  
  Detects hardcoded API keys, passwords, and secrets.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.hardcoded_secrets()
      iex> pattern.severity
      :critical
  """
  defdelegate hardcoded_secrets(), to: HardcodedSecrets, as: :pattern
  
  @doc """
  Weak Cryptography - MD5 Usage pattern.
  
  Detects usage of weak MD5 hash algorithm.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.weak_crypto_md5()
      iex> pattern.cwe_id
      "CWE-328"
  """
  def weak_crypto_md5 do
    %Pattern{
      id: "ruby-weak-crypto-md5",
      name: "Weak Cryptography - MD5 Usage",
      description: "Detects usage of weak MD5 hash algorithm",
      type: :cryptographic_failure,
      severity: :medium,
      languages: ["ruby"],
      regex: [
        ~r/Digest::MD5/,
        ~r/OpenSSL::Digest(?:\.new\(['"]MD5['"]\)|::MD5)/,
        ~r/\.md5\s*\(/
      ],
      default_tier: :public,
      cwe_id: "CWE-328",
      owasp_category: "A02:2021",
      recommendation: "Use SHA-256 or SHA-384 for cryptographic hashing. For password hashing, use bcrypt.",
      test_cases: %{
        vulnerable: [
          ~S|Digest::MD5.hexdigest(password)|,
          ~S|OpenSSL::Digest.new('MD5')|,
          ~S|require 'digest'
hash = Digest::MD5.hexdigest(data)|
        ],
        safe: [
          ~S|Digest::SHA256.hexdigest(data)|,
          ~S|BCrypt::Password.create(password)|,
          ~S|OpenSSL::Digest.new('SHA256')|
        ]
      }
    }
  end
  
  
  @doc """
  SQL Injection via String Interpolation pattern.
  
  Detects SQL queries built with string interpolation.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.sql_injection_interpolation()
      iex> pattern.type
      :sql_injection
  """
  defdelegate sql_injection_interpolation(), to: SqlInjectionInterpolation, as: :pattern
  
  @doc """
  Command Injection pattern.
  
  Detects shell command execution with user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.command_injection()
      iex> pattern.severity
      :critical
  """
  defdelegate command_injection(), to: CommandInjection, as: :pattern
  
  @doc """
  XPath Injection pattern.
  
  Detects XPath queries with user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.xpath_injection()
      iex> pattern.type
      :xpath_injection
  """
  defdelegate xpath_injection(), to: XpathInjection, as: :pattern
  
  @doc """
  LDAP Injection pattern.
  
  Detects LDAP queries with unsanitized user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.ldap_injection()
      iex> pattern.cwe_id
      "CWE-90"
  """
  defdelegate ldap_injection(), to: LdapInjection, as: :pattern
  
  @doc """
  Weak Random Number Generation pattern.
  
  Detects use of predictable random number generators.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.weak_random()
      iex> pattern.severity
      :medium
  """
  defdelegate weak_random(), to: WeakRandom, as: :pattern
  
  @doc """
  Debug Mode Enabled pattern.
  
  Detects debugging code in production.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.debug_mode_enabled()
      iex> pattern.type
      :information_disclosure
  """
  defdelegate debug_mode_enabled(), to: DebugModeEnabled, as: :pattern
  
  @doc """
  Dangerous Eval Usage pattern.
  
  Detects eval usage with user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.eval_usage()
      iex> pattern.severity
      :critical
  """
  defdelegate eval_usage(), to: EvalUsage, as: :pattern
  
  
  
  @doc """
  Weak Password Storage pattern.
  
  Detects insecure password storage methods.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.weak_password_storage()
      iex> pattern.type
      :cryptographic_failure
  """
  defdelegate weak_password_storage(), to: WeakPasswordStorage, as: :pattern
  
  @doc """
  Unsafe Deserialization - Marshal pattern.
  
  Detects unsafe use of Marshal.load with user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.unsafe_deserialization_marshal()
      iex> pattern.severity
      :critical
  """
  defdelegate unsafe_deserialization_marshal(), to: UnsafeDeserializationMarshal, as: :pattern
  
  @doc """
  Unsafe YAML Loading pattern.
  
  Detects unsafe YAML deserialization vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.unsafe_yaml()
      iex> pattern.type
      :deserialization
  """
  defdelegate unsafe_yaml(), to: UnsafeYaml, as: :pattern
  
  @doc """
  Insufficient Security Logging pattern.
  
  Detects missing security event logging that could prevent incident detection.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.insufficient_logging()
      iex> pattern.severity
      :medium
  """
  defdelegate insufficient_logging(), to: InsufficientLogging, as: :pattern
  
  @doc """
  SSRF via open-uri pattern.
  
  Detects Server-Side Request Forgery vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.ssrf_open_uri()
      iex> pattern.type
      :ssrf
  """
  defdelegate ssrf_open_uri(), to: SsrfOpenUri, as: :pattern
  
  @doc """
  XSS in ERB Templates pattern.
  
  Detects cross-site scripting vulnerabilities in ERB.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.xss_erb_raw()
      iex> pattern.type
      :xss
  """
  defdelegate xss_erb_raw(), to: XssErbRaw, as: :pattern
  
  @doc """
  Path Traversal pattern.
  
  Detects file access with user-controlled paths.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.path_traversal()
      iex> pattern.severity
      :high
  """
  defdelegate path_traversal(), to: PathTraversal, as: :pattern
  
  @doc """
  Open Redirect pattern.
  
  Detects unvalidated redirect destinations.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.open_redirect()
      iex> pattern.type
      :open_redirect
  """
  defdelegate open_redirect(), to: OpenRedirect, as: :pattern
  
  @doc """
  Insecure Cookie Settings pattern.
  
  Detects cookies without security flags.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.insecure_cookie()
      iex> pattern.severity
      :medium
  """
  defdelegate insecure_cookie(), to: InsecureCookie, as: :pattern
end