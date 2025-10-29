defmodule RsolvWeb.Api.V1.SafePatternDetector do
  @moduledoc """
  Detects safe coding patterns that are often incorrectly flagged as vulnerabilities.
  Part of RFC-042: AST False Positive Reduction Enhancement.

  This module identifies patterns that use secure coding practices like parameterized
  queries, constant comparisons, and framework-provided escaping mechanisms.
  """

  @doc """
  Checks if a code pattern is actually safe despite matching a vulnerability pattern.

  ## Parameters
    - vulnerability_type: The type of vulnerability detected (:sql_injection, :timing_attack, etc.)
    - code: The code snippet to check
    - context: Additional context (language, framework, etc.)

  ## Examples

      iex> SafePatternDetector.is_safe_pattern?(:timing_attack, "e.code === DOMException.QUOTA_EXCEEDED_ERR", %{language: "javascript"})
      true

      iex> SafePatternDetector.is_safe_pattern?(:sql_injection, "query('SELECT * FROM users WHERE id = $1', [id])", %{language: "javascript"})
      true
  """
  def is_safe_pattern?(vulnerability_type, code, context \\ %{})

  def is_safe_pattern?(:timing_attack, code, %{language: language}) do
    patterns = get_timing_safe_patterns(language)

    # Check for safe patterns
    safe = Enum.any?(patterns, fn pattern -> Regex.match?(pattern, code) end)

    # Also check for unsafe patterns that override safe detection
    unsafe_patterns = [
      # password comparison with non-constant
      ~r/password\s*===?\s*[^A-Z]/,
      # token from request
      ~r/token\s*===?\s*req\./,
      # API key from user
      ~r/apiKey\s*===?\s*user/,
      # secret comparison
      ~r/secret\s*===?\s*[^A-Z]/
    ]

    safe && !Enum.any?(unsafe_patterns, fn pattern -> Regex.match?(pattern, code) end)
  end

  def is_safe_pattern?(:sql_injection, nil, %{language: _language}), do: false
  def is_safe_pattern?(:sql_injection, "", %{language: _language}), do: false

  def is_safe_pattern?(:sql_injection, code, %{language: language}) do
    require Logger

    # First check for definitely unsafe patterns
    unsafe_patterns = get_sql_unsafe_patterns(language)

    # Log which unsafe pattern matches (if any)
    matching_unsafe =
      Enum.find(unsafe_patterns, fn pattern ->
        matches = Regex.match?(pattern, code)

        if matches do
          Logger.debug(
            "SafePatternDetector: Unsafe pattern #{inspect(pattern)} matched code: #{String.slice(code, 0, 100)}"
          )
        end

        matches
      end)

    if matching_unsafe do
      false
    else
      # Then check for safe patterns
      patterns = get_sql_safe_patterns(language)

      has_safe =
        Enum.any?(patterns, fn pattern ->
          matches = Regex.match?(pattern, code)

          if matches do
            Logger.debug("SafePatternDetector: Safe pattern #{inspect(pattern)} matched code")
          end

          matches
        end)

      if has_safe do
        Logger.debug(
          "SafePatternDetector: Code is SAFE (no unsafe patterns matched, safe pattern found)"
        )
      else
        Logger.debug("SafePatternDetector: Code is UNSAFE (no safe patterns matched)")
      end

      has_safe
    end
  end

  def is_safe_pattern?(:nosql_injection, nil, %{language: language})
      when language in ["javascript", "python"],
      do: false

  def is_safe_pattern?(:nosql_injection, "", %{language: language})
      when language in ["javascript", "python"],
      do: false

  def is_safe_pattern?(:nosql_injection, code, %{language: language})
      when language in ["javascript", "python"] do
    patterns = get_nosql_safe_patterns(language)
    safe = Enum.any?(patterns, fn pattern -> Regex.match?(pattern, code) end)

    # Check for dangerous patterns
    has_where = Regex.match?(~r/\$where/, code)
    # Dynamic JSON parsing
    has_user_input =
      Regex.match?(~r/req\.(body|query|params)/, code) ||
        Regex.match?(~r/request\.(POST|GET)/, code) ||
        Regex.match?(~r/json\.loads/, code)

    # Safe only if it matches safe patterns AND doesn't have dangerous inputs
    safe && !has_where && !has_user_input
  end

  def is_safe_pattern?(:nosql_injection, _code, _context), do: false

  def is_safe_pattern?(:xss, nil, %{language: _language}), do: false
  def is_safe_pattern?(:xss, "", %{language: _language}), do: false

  def is_safe_pattern?(:xss, code, %{language: language}) do
    patterns = get_xss_safe_patterns(language)
    has_safe = Enum.any?(patterns, fn pattern -> Regex.match?(pattern, code) end)

    # Check for dangerous HTML insertion WITHOUT escaping
    # Note: We check if escaping functions are present separately
    unsafe_patterns = [
      # document.write with user input
      ~r/document\.write\([^)]*user/i,
      # insertAdjacentHTML
      ~r/insertAdjacentHTML\(/
    ]

    # Check for potentially dangerous patterns that need escaping
    needs_escaping =
      Regex.match?(~r/\.innerHTML\s*=/, code) ||
        Regex.match?(~r/\.outerHTML\s*=/, code)

    has_unsafe = Enum.any?(unsafe_patterns, fn pattern -> Regex.match?(pattern, code) end)

    # Check for explicit escaping/sanitization
    has_escaping =
      Regex.match?(
        ~r/escape|sanitize|DOMPurify|textContent|innerText|createTextNode|React\.createElement/i,
        code
      )

    # Safe if:
    # 1. Has safe patterns OR escaping, AND
    # 2. No definitely unsafe patterns, AND
    # 3. If using innerHTML/outerHTML, must have escaping
    (has_safe || has_escaping) && !has_unsafe && (!needs_escaping || has_escaping)
  end

  def is_safe_pattern?(:code_injection, code, %{language: "javascript"}) do
    # Check for eval with literals or constants
    safe_patterns = [
      # Eval with literal string
      ~r/eval\(['"][\w\s\+\-\*\/\(\)]+['"]\)/,
      # Eval with constant
      ~r/eval\([A-Z_]+\)/,
      # Safe Function constructor
      ~r/new Function\(['"]return/
    ]

    Enum.any?(safe_patterns, fn pattern -> Regex.match?(pattern, code) end)
  end

  def is_safe_pattern?(:command_injection, code, %{language: language})
      when language in ["javascript", "python", "ruby", "php"] do
    # Check for safe command execution patterns
    safe_patterns =
      case language do
        "javascript" ->
          [
            # execFile is safer than exec
            ~r/execFile\(/,
            # spawn with array of args
            ~r/spawn\(['"][^'"]+['"]\s*,\s*\[/,
            # exec with literal string only (no concat)
            ~r/exec\(['"][^'"$`]+['"]\)\s*$/
          ]

        "python" ->
          [
            # subprocess.run with list
            ~r/subprocess\.run\(\[/,
            # subprocess.call with list
            ~r/subprocess\.call\(\[/,
            # os.execv (doesn't use shell)
            ~r/os\.execv/,
            # Explicit check flag
            ~r/check=True/
          ]

        "ruby" ->
          [
            # system with literal string
            ~r/system\(['"][^'"$`]+['"]\)/,
            # Open3 is safer
            ~r/Open3\./
          ]

        "php" ->
          [
            # Command escaping
            ~r/escapeshellcmd/,
            # Argument escaping
            ~r/escapeshellarg/,
            # exec with literal
            ~r/exec\(['"][^'"$`]+['"]\)/
          ]
      end

    # Check for unsafe patterns that override safe detection
    unsafe_patterns = [
      # String concatenation with user variables
      ~r/\+\s*user/,
      # Template literals with user input
      ~r/\$\{.*user/,
      # Command substitution
      ~r/\$\(/,
      # Backticks with variables
      ~r/`.*\$/,
      # Request data
      ~r/req\./,
      # Parameters array access
      ~r/params\[/,
      # shell: true option
      ~r/shell\s*:\s*true/,
      # Python shell=True
      ~r/shell=True/
    ]

    has_safe = Enum.any?(safe_patterns, fn pattern -> Regex.match?(pattern, code) end)
    has_unsafe = Enum.any?(unsafe_patterns, fn pattern -> Regex.match?(pattern, code) end)

    # Only safe if it matches safe patterns AND doesn't match unsafe patterns
    has_safe && !has_unsafe
  end

  def is_safe_pattern?(:command_injection, _code, _context), do: false

  def is_safe_pattern?(:path_traversal, nil, %{language: _language}), do: false
  def is_safe_pattern?(:path_traversal, "", %{language: _language}), do: false

  def is_safe_pattern?(:path_traversal, code, %{language: _language}) do
    # Check for safe sanitization patterns FIRST
    safe_patterns = [
      # path.normalize is always safe
      ~r/path\.normalize\(/,
      # path.resolve is safe
      ~r/path\.resolve\(/,
      # pathlib.Path().resolve() is safe
      ~r/Path\([^)]*\)\.resolve\(/,
      # Using basename (PHP) is safe
      ~r/basename\(/,
      # realpath (PHP) is safe
      ~r/realpath\(/
    ]

    # These patterns are conditionally safe (only with constants/literals)
    conditionally_safe_patterns = [
      # path.join with __dirname
      ~r/path\.join\(__dirname/,
      # path.join with literals
      ~r/path\.join\([^,]*['"][^'"]*['"]/,
      # os.path.join with constants like BASE_DIR
      ~r/os\.path\.join\([A-Z_]+/,
      # os.path.join with literals only
      ~r/os\.path\.join\(['"][^'"]*['"]/,
      # Rails.root.join with literals
      ~r/Rails\.root\.join\(['"][^'"]*['"]/,
      # pathlib.Path is generally safe
      ~r/pathlib\.Path/
    ]

    # Check for definitely unsafe patterns - but exclude safe built-ins
    definitely_unsafe = [
      # request data
      ~r/req\.(query|body|params)/,
      # params hash
      ~r/params\[/,
      # PHP GET params
      ~r/\$_GET/,
      # PHP POST params
      ~r/\$_POST/,
      # Path traversal
      ~r/\.\.\//,
      # user_path or userPath variables
      ~r/user_?[pP]ath/,
      # user_file or userFile variables
      ~r/user_?[fF]ile/
    ]

    # If it uses a safe sanitization method, it's safe regardless of input
    cond do
      Enum.any?(safe_patterns, fn pattern -> Regex.match?(pattern, code) end) ->
        true

      Enum.any?(definitely_unsafe, fn pattern -> Regex.match?(pattern, code) end) ->
        false

      true ->
        # Check conditionally safe patterns
        Enum.any?(conditionally_safe_patterns, fn pattern -> Regex.match?(pattern, code) end)
    end
  end

  def is_safe_pattern?(:ssrf, code, %{language: _language}) do
    # Check for safe URL patterns (constants, not user input)
    safe_patterns = [
      # Literal URL (JS)
      ~r/axios\.get\(['"][^'"]+['"]\)/,
      # Literal URL (JS)
      ~r/fetch\(['"][^'"]+['"]\)/,
      # Template with constants (JS)
      ~r/fetch\(`\$\{[A-Z_]+\}/,
      # Using constants like ${API_BASE}
      ~r/\$\{[A-Z_]+\}/,
      # Environment variables
      ~r/process\.env\.[A-Z_]+/,
      # Python f-string with constants
      ~r/requests\.get\(f['"]\{[A-Z_]+\}/,
      # Python literal URL
      ~r/urlopen\(['"][^'"]+['"]\)/,
      # Localhost URLs
      ~r/localhost|127\.0\.0\.1/
    ]

    # Check for unsafe patterns with user input
    unsafe_patterns = [
      # Request data
      ~r/req\.\w+/,
      # Parameters
      ~r/params\[/,
      # Body data
      ~r/body\./,
      # Query data
      ~r/query\./,
      # User input (camelCase)
      ~r/user[A-Z]/,
      # User input (snake_case)
      ~r/user_/
    ]

    has_safe = Enum.any?(safe_patterns, fn pattern -> Regex.match?(pattern, code) end)
    has_unsafe = Enum.any?(unsafe_patterns, fn pattern -> Regex.match?(pattern, code) end)

    # Only safe if it doesn't have user input
    has_safe && !has_unsafe
  end

  def is_safe_pattern?(:hardcoded_secret, nil, %{language: _language}), do: false
  def is_safe_pattern?(:hardcoded_secret, "", %{language: _language}), do: false

  def is_safe_pattern?(:hardcoded_secret, code, %{language: _language}) do
    # Check for safe patterns - using environment variables, config, or secret managers
    safe_patterns = [
      # Environment variables - JavaScript/TypeScript
      # process.env.API_KEY
      ~r/process\.env\.[A-Z_]+/,
      # Vite: import.meta.env.VITE_API_KEY
      ~r/import\.meta\.env\.[A-Z_]+/,

      # Environment variables - Python
      # os.environ['KEY']
      ~r/os\.environ\[/,
      # os.getenv('KEY')
      ~r/os\.getenv\(/,
      # environ.get('KEY')
      ~r/environ\.get\(/,

      # Environment variables - Ruby
      # ENV['KEY']
      ~r/ENV\[/,
      # ENV.fetch('KEY')
      ~r/ENV\.fetch\(/,

      # Environment variables - PHP
      # $_ENV['KEY']
      ~r/\$_ENV\[/,
      # getenv('KEY')
      ~r/getenv\(/,
      # $_SERVER['API_KEY']
      ~r/\$_SERVER\[['"].*KEY/,

      # Environment variables - Go
      # os.Getenv("KEY")
      ~r/os\.Getenv\(/,
      # os.LookupEnv("KEY")
      ~r/os\.LookupEnv\(/,

      # Environment variables - Java
      # System.getenv("KEY")
      ~r/System\.getenv\(/,
      # System.getProperty("key")
      ~r/System\.getProperty\(/,

      # Environment variables - Rust
      # env::var("KEY")
      ~r/env::var\(/,
      # std::env::var("KEY")
      ~r/std::env::var\(/,

      # Environment variables - Elixir
      # System.get_env("KEY")
      ~r/System\.get_env\(/,
      # System.fetch_env!("KEY")
      ~r/System\.fetch_env!\(/,

      # Config files - JavaScript/TypeScript
      # config.get('key')
      ~r/config\.get\(/,
      # process.env[key]
      ~r/process\.env\[/,
      # require('config')
      ~r/require\(['"]config['"]\)/,

      # Config files - Python
      # Django: settings.SECRET_KEY
      ~r/settings\.[A-Z_]+/,
      # config['key']
      ~r/config\[/,
      # ConfigParser usage
      ~r/ConfigParser/,

      # Config files - Ruby
      # Rails credentials
      ~r/Rails\.application\.credentials/,
      # Rails secrets
      ~r/Rails\.application\.secrets/,
      # Config gem
      ~r/Config\./,

      # Config files - PHP
      # Laravel: config('app.key')
      ~r/config\(/,
      # Config::get('key')
      ~r/Config::get\(/,

      # Config files - Go
      # Viper config
      ~r/viper\./,
      # godotenv usage
      ~r/godotenv/,

      # Config files - Java
      # Properties file
      ~r/Properties\(\)/,
      # Spring @Value
      ~r/@Value\(/,
      # Spring properties
      ~r/application\.properties/,

      # Config files - Rust
      # config crate
      ~r/Config::builder\(/,
      # dotenv usage
      ~r/dotenv\(\)/,

      # Config files - Elixir
      # Application.get_env()
      ~r/Application\.get_env\(/,
      # Application.fetch_env!()
      ~r/Application\.fetch_env!\(/,
      # config :app, key: value
      ~r/config :[\w]+,/,

      # Secret managers
      # AWS Secrets Manager
      ~r/secretsManager\./,
      # AWS SDK
      ~r/SecretsManager/,
      # Azure Key Vault
      ~r/key_vault\./,
      # Azure SDK
      ~r/KeyVault/,
      # HashiCorp Vault
      ~r/vault\./,
      # Google Secret Manager
      ~r/SecretManager\./,
      # AWS KMS
      ~r/KMS\./,
      # AWS Parameter Store
      ~r/ParameterStore/,

      # Framework-specific secure patterns
      # Rails secrets
      ~r/Rails\.application\.secrets/,
      # Python keyring
      ~r/Keyring\./,
      # macOS Keychain
      ~r/keychain\./,
      # AWS credential process
      ~r/credential_process/,

      # Config loaders
      # dotenv library
      ~r/dotenv/,
      # python-decouple
      ~r/decouple/,
      # environs library
      ~r/environs/
    ]

    # Check for unsafe patterns - hardcoded secrets
    unsafe_patterns = [
      # Common secret patterns
      # Long alphanumeric strings
      ~r/['"][a-zA-Z0-9]{32,}['"]/,
      # Stripe-like keys
      ~r/sk[-_][a-zA-Z0-9]+/,
      # AWS access keys
      ~r/AKIA[A-Z0-9]+/,
      # GitHub personal tokens
      ~r/ghp_[a-zA-Z0-9]+/,
      # GitLab tokens
      ~r/glpat-[a-zA-Z0-9]+/,
      # Bearer tokens
      ~r/['"]Bearer\s+[a-zA-Z0-9\-._]+['"]/,

      # Password patterns
      # password = "something"
      ~r/password\s*[:=]\s*['"][^'"]+['"]/,
      # passwd = "something"
      ~r/passwd\s*[:=]\s*['"][^'"]+['"]/,
      # pwd = "something"
      ~r/pwd\s*[:=]\s*['"][^'"]+['"]/,

      # API key patterns
      # api_key = "something"
      ~r/api_?key\s*[:=]\s*['"][^'"]+['"]/i,
      # apikey = "something"
      ~r/apikey\s*[:=]\s*['"][^'"]+['"]/i,
      # token = "something"
      ~r/token\s*[:=]\s*['"][^'"]+['"]/,
      # secret = "something"
      ~r/secret\s*[:=]\s*['"][^'"]+['"]/
    ]

    has_safe = Enum.any?(safe_patterns, fn pattern -> Regex.match?(pattern, code) end)
    has_unsafe = Enum.any?(unsafe_patterns, fn pattern -> Regex.match?(pattern, code) end)

    # It's safe if it uses safe patterns and doesn't have hardcoded values
    has_safe && !has_unsafe
  end

  # Default case - not recognized as safe
  def is_safe_pattern?(_vulnerability_type, _code, _context), do: false

  # Private helper functions

  defp get_timing_safe_patterns("javascript"),
    do: [
      # Constant comparison
      ~r/===\s+[A-Z][A-Z_]+/,
      # Module constant
      ~r/===\s+\w+\.[A-Z]/,
      # DOMException constants
      ~r/\.code\s*===\s*DOMException\./,
      # HTTP status codes
      ~r/\.status\s*===\s*\d+/,
      # Numeric literal comparison
      ~r/===\s*\d+/,
      # Numeric literal not-equal
      ~r/!==\s*\d+/,
      # Any variable compared to number
      ~r/\w+\s*===\s*\d+/
    ]

  defp get_timing_safe_patterns("python"),
    do: [
      # Constant comparison
      ~r/==\s+[A-Z][A-Z_]+/,
      # Module constant
      ~r/==\s+\w+\.[A-Z]/,
      # HTTP status codes
      ~r/\.status_code\s*==\s*\d+/
    ]

  defp get_timing_safe_patterns("ruby"),
    do: [
      # Constant comparison
      ~r/==\s+[A-Z][A-Z_]+/,
      # Module constant
      ~r/==\s+::\w+/,
      # HTTP status codes
      ~r/\.status\s*==\s*\d+/
    ]

  defp get_timing_safe_patterns("php"),
    do: [
      # Constant comparison
      ~r/===\s+[A-Z][A-Z_]+/,
      # Class constant
      ~r/===\s+\w+::[A-Z]/,
      # HTTP status codes
      ~r/->getStatusCode\(\)\s*===\s*\d+/
    ]

  defp get_timing_safe_patterns(_), do: []

  defp get_sql_unsafe_patterns("javascript"),
    do: [
      # SELECT with concatenation
      ~r/SELECT.*\+\s*\w+/i,
      # WHERE with concatenation
      ~r/WHERE.*\+\s*\w+/i,
      # VALUES with concatenation
      ~r/VALUES.*\+\s*\w+/i,
      # FROM with concatenation
      ~r/FROM\s+['"]?\s*\+\s*/i,
      # query() with concatenation
      ~r/query\([^,]*\+[^,]*\)/,
      # Timing attack vulnerability on same line
      ~r/password\s*===\s*\w+Password/,
      # API key comparison on same line
      ~r/apiKey\s*===/,
      # Token comparison on same line
      ~r/token\s*===/
    ]

  defp get_sql_unsafe_patterns("python"),
    do: [
      # SELECT with % formatting (not parameterized)
      ~r/SELECT.*["']\s*%\s*\w+/i,
      # WHERE with % formatting (not parameterized)
      ~r/WHERE.*["']\s*%\s*\w+/i,
      # VALUES with % formatting (not parameterized)
      ~r/VALUES.*["']\s*%\s*\w+/i,
      # execute() with % formatting without params
      ~r/execute\([^,]+["']\s*%\s*[^,)]+\)$/,
      # f-string in SQL
      ~r/SELECT.*f["']/i,
      # f-string in WHERE
      ~r/WHERE.*f["']/i
    ]

  defp get_sql_unsafe_patterns("ruby"),
    do: [
      # SELECT with interpolation
      ~r/SELECT.*#\{/i,
      # WHERE with interpolation
      ~r/WHERE.*#\{/i,
      # VALUES with interpolation
      ~r/VALUES.*#\{/i,
      # exec() with concatenation
      ~r/exec\([^,]*\+[^,]*\)/
    ]

  defp get_sql_unsafe_patterns("php"),
    do: [
      # SELECT with concatenation
      ~r/SELECT.*\.\s*\$/i,
      # WHERE with concatenation
      ~r/WHERE.*\.\s*\$/i,
      # VALUES with concatenation
      ~r/VALUES.*\.\s*\$/i,
      # query() with concatenation
      ~r/query\([^,]*\.\s*\$/
    ]

  defp get_sql_unsafe_patterns(_), do: []

  defp get_sql_safe_patterns("javascript"),
    do: [
      # PostgreSQL params ($1, $2)
      ~r/\$\d+/,
      # MySQL params (?) - either followed by comma/paren or in string with params
      ~r/\?\s*[,\)]/,
      ~r/\?['"].*,\s*\[/,
      # Named params (:id, :name)
      ~r/:\w+/,
      # Parameterized query with array
      ~r/\.query\([^,]+,\s*\[/,
      # Prepared statements
      ~r/\.prepare\(/
    ]

  defp get_sql_safe_patterns("python"),
    do: [
      # Parameterized execute with params
      ~r/\.execute\([^,]+,\s*[\[\(]/,
      # Parameterized executemany
      ~r/\.executemany\([^,]+,\s*[\[\(]/,
      # SQLite params when not using %
      ~r/\?\s*[,\)]/,
      # Named params
      ~r/:\w+/,
      # Django ORM filter
      ~r/\.objects\.filter\(/,
      # Django ORM get
      ~r/\.objects\.get\(/,
      # Django ORM all
      ~r/\.objects\.all\(/
    ]

  defp get_sql_safe_patterns("ruby"),
    do: [
      # Placeholder params
      ~r/\?\s*[,\)]/,
      # Named params
      ~r/:\w+/,
      # Rails where with params
      ~r/\.where\([^,]+,\s*[\[\{]/
    ]

  defp get_sql_safe_patterns("php"),
    do: [
      # PDO placeholders
      ~r/\?\s*[,\)]/,
      # PDO named params
      ~r/:\w+/,
      # Prepared statements
      ~r/->prepare\(/,
      # mysqli bind
      ~r/->bind_param\(/
    ]

  defp get_sql_safe_patterns(_), do: []

  defp get_nosql_safe_patterns("javascript"),
    do: [
      # No $where
      ~r/\.find\(\{[^$]*\}\)/,
      # No $where
      ~r/\.findOne\(\{[^$]*\}\)/,
      # Safe findById
      ~r/\.findById\(/,
      # No $where in update
      ~r/\.updateOne\(\{[^$]*\}\)/
    ]

  defp get_nosql_safe_patterns("python"),
    do: [
      # No $where
      ~r/\.find\(\{[^$]*\}\)/,
      # No $where
      ~r/\.find_one\(\{[^$]*\}\)/
    ]

  defp get_nosql_safe_patterns(_), do: []

  defp get_xss_safe_patterns("javascript"),
    do: [
      # Safe text content
      ~r/\.textContent\s*=/,
      # Safe inner text
      ~r/\.innerText\s*=/,
      # Template rendering (usually safe)
      ~r/\.render\(/,
      # Escaping function
      ~r/escape\(/,
      # Sanitization
      ~r/sanitize\(/,
      # jQuery .text() method
      ~r/\$\([^)]+\)\.text\(/,
      # DOM createTextNode
      ~r/createTextNode\(/,
      # React createElement is safe by default
      ~r/React\.createElement\(/
    ]

  defp get_xss_safe_patterns("python"),
    do: [
      # Escaping
      ~r/escape\(/,
      # Markup escape
      ~r/markup\.escape\(/,
      # Template rendering
      ~r/\.render\(/
    ]

  defp get_xss_safe_patterns("ruby"),
    do: [
      # Rails html_safe
      ~r/html_safe/,
      # HTML escaping
      ~r/escape_html\(/,
      # Rails h() helper
      ~r/h\(/
    ]

  defp get_xss_safe_patterns("php"),
    do: [
      # PHP escaping
      ~r/htmlspecialchars\(/,
      # PHP entities
      ~r/htmlentities\(/,
      # Input filtering
      ~r/filter_var\(/
    ]

  defp get_xss_safe_patterns(_), do: []

  @doc """
  Explains why a pattern was considered safe or unsafe.
  """
  def explain_safety(vulnerability_type, code, context) do
    if is_safe_pattern?(vulnerability_type, code, context) do
      case vulnerability_type do
        :timing_attack -> "Comparing against a constant value - not a timing vulnerability"
        :sql_injection -> "Using parameterized query - protected from SQL injection"
        :nosql_injection -> "Safe MongoDB query without dangerous operators"
        :xss -> "Proper escaping or safe DOM method used"
        :code_injection -> "Eval with literal or constant - not user-controlled"
        :command_injection -> "Safe command execution pattern"
        :path_traversal -> "Path is properly sanitized"
        :ssrf -> "Using constant URL - not user-controlled"
        :hardcoded_secret -> "Using environment variable or config - not hardcoded"
        _ -> "Pattern recognized as safe"
      end
    else
      case vulnerability_type do
        :timing_attack -> "String comparison could be timing-sensitive"
        :sql_injection -> "Potential SQL injection - use parameterized queries"
        :nosql_injection -> "Potential NoSQL injection - avoid $where operator"
        :xss -> "Potential XSS - ensure proper escaping"
        :code_injection -> "Potential code injection - avoid eval with user input"
        :command_injection -> "Potential command injection - use safe execution methods"
        :path_traversal -> "Potential path traversal - sanitize file paths"
        :ssrf -> "Potential SSRF - validate and whitelist URLs"
        :hardcoded_secret -> "Potential hardcoded secret - use environment variables"
        _ -> "Pattern may be vulnerable"
      end
    end
  end

  @doc """
  Returns confidence adjustment based on pattern safety.
  Safe patterns get very low confidence (likely false positive).
  """
  def confidence_adjustment(vulnerability_type, code, context) do
    if is_safe_pattern?(vulnerability_type, code, context) do
      # 90% reduction for safe patterns
      0.1
    else
      # No adjustment for potentially unsafe patterns
      1.0
    end
  end
end
