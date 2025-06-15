defmodule RsolvApi.Security.Patterns.Elixir do
  @moduledoc """
  Elixir security patterns for detecting vulnerabilities.
  
  This module contains 28 security patterns specifically designed for Elixir
  and Phoenix code. Each pattern includes detection rules, test cases, and 
  educational documentation.
  """
  
  alias RsolvApi.Security.Pattern
  alias RsolvApi.Security.Patterns.Elixir.SqlInjectionInterpolation
  alias RsolvApi.Security.Patterns.Elixir.SqlInjectionFragment
  alias RsolvApi.Security.Patterns.Elixir.CommandInjectionSystem
  alias RsolvApi.Security.Patterns.Elixir.XssRawHtml
  alias RsolvApi.Security.Patterns.Elixir.InsecureRandom
  alias RsolvApi.Security.Patterns.Elixir.UnsafeAtomCreation
  alias RsolvApi.Security.Patterns.Elixir.CodeInjectionEval
  alias RsolvApi.Security.Patterns.Elixir.DeserializationErlang
  alias RsolvApi.Security.Patterns.Elixir.PathTraversal
  alias RsolvApi.Security.Patterns.Elixir.SsrfHttpoison
  alias RsolvApi.Security.Patterns.Elixir.WeakCryptoMd5
  alias RsolvApi.Security.Patterns.Elixir.WeakCryptoSha1
  alias RsolvApi.Security.Patterns.Elixir.MissingCsrfProtection
  
  @doc """
  Returns all Elixir security patterns.
  
  ## Examples
  
      iex> patterns = RsolvApi.Security.Patterns.Elixir.all()
      iex> length(patterns)
      28
      iex> Enum.all?(patterns, &match?(%Pattern{}, &1))
      true
  """
  def all do
    [
      sql_injection_interpolation(),
      sql_injection_fragment(),
      command_injection_system(),
      xss_raw_html(),
      insecure_random(),
      unsafe_atom_creation(),
      code_injection_eval(),
      deserialization_erlang(),
      path_traversal(),
      ssrf_httpoison(),
      weak_crypto_md5(),
      weak_crypto_sha1(),
      missing_csrf_protection(),
      debug_mode_enabled(),
      unsafe_process_spawn(),
      atom_exhaustion(),
      ets_public_table(),
      missing_auth_pipeline(),
      unsafe_redirect(),
      hardcoded_secrets(),
      unsafe_json_decode(),
      cookie_security(),
      unsafe_file_upload(),
      insufficient_input_validation(),
      exposed_error_details(),
      unsafe_genserver_calls(),
      missing_ssl_verification(),
      weak_password_hashing()
    ]
  end
  
  # Delegate to the SqlInjectionInterpolation module
  defdelegate sql_injection_interpolation(), to: SqlInjectionInterpolation, as: :pattern
  
  # Delegate to the SqlInjectionFragment module
  defdelegate sql_injection_fragment(), to: SqlInjectionFragment, as: :pattern
  
  # Delegate to the CommandInjectionSystem module  
  defdelegate command_injection_system(), to: CommandInjectionSystem, as: :pattern
  
  # Delegate to the XssRawHtml module
  defdelegate xss_raw_html(), to: XssRawHtml, as: :pattern
  
  # Delegate to the InsecureRandom module
  defdelegate insecure_random(), to: InsecureRandom, as: :pattern
  
  # Delegate to the UnsafeAtomCreation module
  defdelegate unsafe_atom_creation(), to: UnsafeAtomCreation, as: :pattern
  
  # Delegate to the CodeInjectionEval module
  defdelegate code_injection_eval(), to: CodeInjectionEval, as: :pattern
  
  # Delegate to the DeserializationErlang module
  defdelegate deserialization_erlang(), to: DeserializationErlang, as: :pattern
  
  # Delegate to the PathTraversal module
  defdelegate path_traversal(), to: PathTraversal, as: :pattern
  
  # Delegate to the SsrfHttpoison module
  defdelegate ssrf_httpoison(), to: SsrfHttpoison, as: :pattern
  
  
  # Delegate to the WeakCryptoMd5 module
  defdelegate weak_crypto_md5(), to: WeakCryptoMd5, as: :pattern
  
  # Delegate to the WeakCryptoSha1 module
  defdelegate weak_crypto_sha1(), to: WeakCryptoSha1, as: :pattern

  # Delegate to the MissingCsrfProtection module
  defdelegate missing_csrf_protection(), to: MissingCsrfProtection, as: :pattern
  
  
  @doc """
  Debug Mode Enabled pattern.
  
  Detects debug mode or sensitive information exposure.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Elixir.debug_mode_enabled()
      iex> vulnerable = ~S|config :my_app, debug: true|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def debug_mode_enabled do
    %Pattern{
      id: "elixir-debug-mode-enabled",
      name: "Debug Mode Enabled",
      description: "Debug mode can expose sensitive information",
      type: :information_disclosure,
      severity: :medium,
      languages: ["elixir"],
      regex: ~r/config\s+.*debug:\s*true|IO\.inspect\s*\(/,
      default_tier: :public,
      cwe_id: "CWE-489",
      owasp_category: "A05:2021",
      recommendation: "Disable debug mode in production. Remove IO.inspect calls",
      test_cases: %{
        vulnerable: [
          ~S|config :my_app, debug: true|,
          ~S|IO.inspect(sensitive_data, label: "DEBUG")|
        ],
        safe: [
          ~S|config :my_app, debug: false|,
          ~S|Logger.debug("Debug info: #{inspect(data)}")|
        ]
      }
    }
  end
  
  @doc """
  Unsafe Process Spawn pattern.
  
  Detects unsafe process spawning that might not be linked.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Elixir.unsafe_process_spawn()
      iex> vulnerable = ~S|spawn(fn -> execute_user_code(input) end)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def unsafe_process_spawn do
    %Pattern{
      id: "elixir-unsafe-process-spawn",
      name: "Unsafe Process Spawning",
      description: "Unlinked processes can crash without supervision",
      type: :resource_exhaustion,
      severity: :medium,
      languages: ["elixir"],
      regex: ~r/spawn\s*\(\s*fn/,
      default_tier: :protected,
      cwe_id: "CWE-400",
      owasp_category: "A05:2021",
      recommendation: "Use Task.start_link/1 or spawn_link/1 for supervised processes",
      test_cases: %{
        vulnerable: [
          ~S|spawn(fn -> execute_user_code(input) end)|
        ],
        safe: [
          ~S|Task.start_link(fn -> execute_user_code(input) end)|,
          ~S|spawn_link(fn -> execute_user_code(input) end)|
        ]
      }
    }
  end
  
  @doc """
  Atom Exhaustion pattern.
  
  Detects potential atom table exhaustion vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Elixir.atom_exhaustion()
      iex> vulnerable = ~S|Jason.decode!(user_input, keys: :atoms)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def atom_exhaustion do
    %Pattern{
      id: "elixir-atom-exhaustion",
      name: "Atom Table Exhaustion Risk",
      description: "Converting user input to atoms can exhaust the atom table",
      type: :resource_exhaustion,
      severity: :high,
      languages: ["elixir"],
      regex: ~r/Jason\.decode!?\s*\([^,]+,\s*keys:\s*:atoms/,
      default_tier: :protected,
      cwe_id: "CWE-400",
      owasp_category: "A05:2021",
      recommendation: "Use Jason.decode!(data) without atom keys or use :atoms! for known keys only",
      test_cases: %{
        vulnerable: [
          ~S|Jason.decode!(user_input, keys: :atoms)|
        ],
        safe: [
          ~S|Jason.decode!(user_input)|,
          ~S|Jason.decode!(user_input, keys: :atoms!)|
        ]
      }
    }
  end
  
  @doc """
  ETS Public Table pattern.
  
  Detects potentially unsafe public ETS tables.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Elixir.ets_public_table()
      iex> vulnerable = ~S|:ets.new(:sessions, [:public, :named_table])|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def ets_public_table do
    %Pattern{
      id: "elixir-ets-public-table",
      name: "Public ETS Table Security Risk",
      description: "Public ETS tables can be accessed by any process",
      type: :authentication,
      severity: :medium,
      languages: ["elixir"],
      regex: ~r/:ets\.new\s*\([^,]+,\s*\[[^\]]*:public/,
      default_tier: :protected,
      cwe_id: "CWE-732",
      owasp_category: "A01:2021",
      recommendation: "Use :protected or :private for sensitive data in ETS tables",
      test_cases: %{
        vulnerable: [
          ~S|:ets.new(:sessions, [:public, :named_table])|
        ],
        safe: [
          ~S|:ets.new(:sessions, [:protected, :named_table])|,
          ~S|:ets.new(:cache, [:private])|
        ]
      }
    }
  end
  
  @doc """
  Missing Authentication Pipeline pattern.
  
  Detects Phoenix controllers without authentication.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Elixir.missing_auth_pipeline()
      iex> vulnerable = "defmodule MyAppWeb.AdminController do\\n  use MyAppWeb, :controller\\n  def index(conn, _params) do"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def missing_auth_pipeline do
    %Pattern{
      id: "elixir-missing-auth-pipeline",
      name: "Missing Authentication Pipeline",
      description: "Controllers without authentication pipelines are vulnerable",
      type: :authentication,
      severity: :high,
      languages: ["elixir"],
      frameworks: ["phoenix"],
      regex: ~r/defmodule\s+\w+Web\.(?:Admin|User|Account)Controller\s+do(?:(?!plug\s+:authenticate).)*?def\s+/s,
      default_tier: :protected,
      cwe_id: "CWE-306",
      owasp_category: "A01:2021",
      recommendation: "Add authentication plugs to protect sensitive controllers",
      test_cases: %{
        vulnerable: [
          ~S|defmodule MyAppWeb.AdminController do
  use MyAppWeb, :controller
  
  def index(conn, _params) do|
        ],
        safe: [
          ~S|defmodule MyAppWeb.AdminController do
  use MyAppWeb, :controller
  
  plug :authenticate_admin
  
  def index(conn, _params) do|
        ]
      }
    }
  end
  
  @doc """
  Unsafe Redirect pattern.
  
  Detects open redirect vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Elixir.unsafe_redirect()
      iex> vulnerable = ~S|redirect(conn, external: params["return_to"])|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def unsafe_redirect do
    %Pattern{
      id: "elixir-unsafe-redirect",
      name: "Open Redirect Vulnerability",
      description: "Unvalidated redirects can lead to phishing attacks",
      type: :open_redirect,
      severity: :medium,
      languages: ["elixir"],
      regex: ~r/redirect\s*\(\s*conn\s*,\s*external:\s*params/,
      default_tier: :public,
      cwe_id: "CWE-601",
      owasp_category: "A01:2021",
      recommendation: "Validate redirect URLs against an allowlist",
      test_cases: %{
        vulnerable: [
          ~S|redirect(conn, external: params["return_to"])|
        ],
        safe: [
          ~S|if URI.parse(url).host in @allowed_hosts do
  redirect(conn, external: url)
else
  redirect(conn, to: Routes.home_path(conn, :index))
end|
        ]
      }
    }
  end
  
  @doc """
  Hardcoded Secrets pattern.
  
  Detects hardcoded secrets in source code.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Elixir.hardcoded_secrets()
      iex> vulnerable = ~S|@api_key "sk_live_abcd1234efgh5678"|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def hardcoded_secrets do
    %Pattern{
      id: "elixir-hardcoded-secrets",
      name: "Hardcoded Secrets",
      description: "Secrets should not be hardcoded in source code",
      type: :hardcoded_secret,
      severity: :critical,
      languages: ["elixir"],
      regex: ~r/@(api_key|secret|password|token)\s+"[^"]{16,}"/,
      default_tier: :public,
      cwe_id: "CWE-798",
      owasp_category: "A02:2021",
      recommendation: "Use environment variables or runtime configuration",
      test_cases: %{
        vulnerable: [
          ~S|@api_key "sk_live_abcd1234efgh5678"|,
          ~S|@secret_key_base "a1b2c3d4e5f6g7h8i9j0"|
        ],
        safe: [
          ~S|@api_key System.get_env("API_KEY")|,
          ~S|secret_key_base: System.fetch_env!("SECRET_KEY_BASE")|
        ]
      }
    }
  end
  
  @doc """
  Unsafe JSON Decode pattern.
  
  Detects unsafe JSON decoding that might raise.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Elixir.unsafe_json_decode()
      iex> vulnerable = ~S|Jason.decode!(user_input)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def unsafe_json_decode do
    %Pattern{
      id: "elixir-unsafe-json-decode",
      name: "Unsafe JSON Decoding",
      description: "decode! can crash the process on invalid input",
      type: :dos,
      severity: :low,
      languages: ["elixir"],
      regex: ~r/Jason\.decode!\s*\(\s*[^")]/,
      default_tier: :public,
      cwe_id: "CWE-20",
      owasp_category: "A05:2021",
      recommendation: "Use Jason.decode/1 and handle the error case",
      test_cases: %{
        vulnerable: [
          ~S|Jason.decode!(user_input)|
        ],
        safe: [
          ~S|case Jason.decode(user_input) do
  {:ok, data} -> process(data)
  {:error, _} -> {:error, "Invalid JSON"}
end|
        ]
      }
    }
  end
  
  @doc """
  Cookie Security pattern.
  
  Detects insecure cookie configuration.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Elixir.cookie_security()
      iex> vulnerable = ~S|put_resp_cookie(conn, "session", value)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def cookie_security do
    %Pattern{
      id: "elixir-cookie-security",
      name: "Insecure Cookie Configuration",
      description: "Cookies without secure flags are vulnerable",
      type: :session_management,
      severity: :medium,
      languages: ["elixir"],
      regex: ~r/put_resp_cookie\s*\(\s*conn\s*,\s*"[^"]+"\s*,\s*[^,]+\s*\)(?!\s*,)/,
      default_tier: :public,
      cwe_id: "CWE-614",
      owasp_category: "A05:2021",
      recommendation: "Set secure: true, http_only: true, and same_site options",
      test_cases: %{
        vulnerable: [
          ~S|put_resp_cookie(conn, "session", value)|
        ],
        safe: [
          ~S|put_resp_cookie(conn, "session", value, secure: true, http_only: true, same_site: "Strict")|
        ]
      }
    }
  end
  
  @doc """
  Unsafe File Upload pattern.
  
  Detects potential file upload vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Elixir.unsafe_file_upload()
      iex> pattern.id
      "elixir-unsafe-file-upload"
      iex> pattern.severity
      :high
  """
  def unsafe_file_upload do
    %Pattern{
      id: "elixir-unsafe-file-upload",
      name: "Unsafe File Upload",
      description: "File uploads without validation can be dangerous",
      type: :file_upload,
      severity: :high,
      languages: ["elixir"],
      regex: ~r/File\.write!?\s*\([^,]+#\{[^}]*\.filename/,
      default_tier: :protected,
      cwe_id: "CWE-434",
      owasp_category: "A01:2021",
      recommendation: "Validate file types, sanitize filenames, and use a safe upload directory",
      test_cases: %{
        vulnerable: [
          ~S|File.write!("/uploads/#{upload.filename}", upload.content)|
        ],
        safe: [
          ~S|if Path.extname(upload.filename) in [".jpg", ".png"] do
  safe_name = "#{UUID.generate()}_#{Path.basename(upload.filename)}"
  File.write!(Path.join(upload_dir, safe_name), upload.content)
end|
        ]
      }
    }
  end
  
  @doc """
  Insufficient Input Validation pattern.
  
  Detects missing input validation in changesets.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Elixir.insufficient_input_validation()
      iex> vulnerable = ~S|cast(user, params, [:email, :password, :role])|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def insufficient_input_validation do
    %Pattern{
      id: "elixir-insufficient-input-validation",
      name: "Insufficient Input Validation",
      description: "Casting sensitive fields without validation",
      type: :input_validation,
      severity: :medium,
      languages: ["elixir"],
      regex: ~r/cast\s*\([^,]+,\s*[^,]+,\s*\[[^\]]*:role/,
      default_tier: :protected,
      cwe_id: "CWE-20",
      owasp_category: "A03:2021",
      recommendation: "Validate all user inputs, especially sensitive fields like roles",
      test_cases: %{
        vulnerable: [
          ~S|cast(user, params, [:email, :password, :role])|
        ],
        safe: [
          ~S"""
user
|> cast(params, [:email, :password])
|> validate_required([:email, :password])
|> validate_format(:email, ~r/@/)
|> validate_length(:password, min: 8)
"""
        ]
      }
    }
  end
  
  @doc """
  Exposed Error Details pattern.
  
  Detects error messages that might expose sensitive information.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Elixir.exposed_error_details()
      iex> pattern.id
      "elixir-exposed-error-details"
      iex> pattern.severity
      :low
  """
  def exposed_error_details do
    %Pattern{
      id: "elixir-exposed-error-details",
      name: "Exposed Error Details",
      description: "Detailed error messages can reveal system information",
      type: :information_disclosure,
      severity: :low,
      languages: ["elixir"],
      regex: ~r/send_resp\s*\([^,]+,\s*[45]\d\d\s*,\s*["'][^"']*#\{[^}]*error/,
      default_tier: :public,
      cwe_id: "CWE-209",
      owasp_category: "A05:2021",
      recommendation: "Use generic error messages in production",
      test_cases: %{
        vulnerable: [
          ~S|send_resp(conn, 500, "Database error: #{error.message}")|
        ],
        safe: [
          ~S|Logger.error("Database error: #{inspect(error)}")
send_resp(conn, 500, "Internal server error")|
        ]
      }
    }
  end
  
  @doc """
  Unsafe GenServer Calls pattern.
  
  Detects potentially unsafe GenServer calls with user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Elixir.unsafe_genserver_calls()
      iex> vulnerable = ~S|GenServer.call(pid, {:execute, user_command})|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def unsafe_genserver_calls do
    %Pattern{
      id: "elixir-unsafe-genserver-calls",
      name: "Unsafe GenServer Calls",
      description: "Unvalidated GenServer calls can be dangerous",
      type: :rce,
      severity: :medium,
      languages: ["elixir"],
      regex: ~r/GenServer\.call\s*\([^,]+,\s*\{:execute/,
      default_tier: :protected,
      cwe_id: "CWE-94",
      owasp_category: "A03:2021",
      recommendation: "Validate and sanitize all GenServer call parameters",
      test_cases: %{
        vulnerable: [
          ~S|GenServer.call(pid, {:execute, user_command})|
        ],
        safe: [
          ~S|case validate_command(user_command) do
  {:ok, safe_command} -> GenServer.call(pid, {:execute, safe_command})
  :error -> {:error, :invalid_command}
end|
        ]
      }
    }
  end
  
  @doc """
  Missing SSL Verification pattern.
  
  Detects disabled SSL certificate verification.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Elixir.missing_ssl_verification()
      iex> vulnerable = ~S|HTTPoison.get!(url, [], ssl: [verify: :verify_none])|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def missing_ssl_verification do
    %Pattern{
      id: "elixir-missing-ssl-verification",
      name: "Missing SSL Certificate Verification",
      description: "Disabled SSL verification enables MITM attacks",
      type: :authentication,
      severity: :high,
      languages: ["elixir"],
      regex: ~r/ssl:\s*\[.*verify:\s*:verify_none/,
      default_tier: :public,
      cwe_id: "CWE-295",
      owasp_category: "A07:2021",
      recommendation: "Always verify SSL certificates in production",
      test_cases: %{
        vulnerable: [
          ~S|HTTPoison.get!(url, [], ssl: [verify: :verify_none])|
        ],
        safe: [
          ~S|HTTPoison.get!(url)|,
          ~S|HTTPoison.get!(url, [], ssl: [verify: :verify_peer])|
        ]
      }
    }
  end
  
  @doc """
  Weak Password Hashing pattern.
  
  Detects weak password hashing implementations.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Elixir.weak_password_hashing()
      iex> vulnerable = ~S|:crypto.hash(:sha256, password <> salt)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def weak_password_hashing do
    %Pattern{
      id: "elixir-weak-password-hashing",
      name: "Weak Password Hashing",
      description: "Simple hashing is insufficient for passwords",
      type: :weak_crypto,
      severity: :high,
      languages: ["elixir"],
      regex: ~r/:crypto\.hash\s*\(\s*:\w+\s*,\s*password/,
      default_tier: :public,
      cwe_id: "CWE-916",
      owasp_category: "A02:2021",
      recommendation: "Use Argon2 or Bcrypt for password hashing",
      test_cases: %{
        vulnerable: [
          ~S|:crypto.hash(:sha256, password <> salt)|
        ],
        safe: [
          ~S|Argon2.hash_pwd_salt(password)|,
          ~S|Bcrypt.hash_pwd_salt(password)|
        ]
      }
    }
  end
end