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
      ~r/password\s*===?\s*[^A-Z]/,  # password comparison with non-constant
      ~r/token\s*===?\s*req\./,       # token from request
      ~r/apiKey\s*===?\s*user/,       # API key from user
      ~r/secret\s*===?\s*[^A-Z]/,     # secret comparison
    ]
    
    safe && !Enum.any?(unsafe_patterns, fn pattern -> Regex.match?(pattern, code) end)
  end
  
  def is_safe_pattern?(:sql_injection, nil, %{language: _language}), do: false
  def is_safe_pattern?(:sql_injection, "", %{language: _language}), do: false

  def is_safe_pattern?(:sql_injection, code, %{language: language}) do
    # First check for definitely unsafe patterns
    unsafe_patterns = get_sql_unsafe_patterns(language)
    is_unsafe = Enum.any?(unsafe_patterns, fn pattern -> Regex.match?(pattern, code) end)

    if is_unsafe do
      false
    else
      # Then check for safe patterns
      patterns = get_sql_safe_patterns(language)
      Enum.any?(patterns, fn pattern -> Regex.match?(pattern, code) end)
    end
  end
  
  def is_safe_pattern?(:nosql_injection, nil, %{language: language}) when language in ["javascript", "python"], do: false
  def is_safe_pattern?(:nosql_injection, "", %{language: language}) when language in ["javascript", "python"], do: false

  def is_safe_pattern?(:nosql_injection, code, %{language: language}) when language in ["javascript", "python"] do
    patterns = get_nosql_safe_patterns(language)
    safe = Enum.any?(patterns, fn pattern -> Regex.match?(pattern, code) end)

    # Check for dangerous patterns
    has_where = Regex.match?(~r/\$where/, code)
    has_user_input = Regex.match?(~r/req\.(body|query|params)/, code) ||
                     Regex.match?(~r/request\.(POST|GET)/, code) ||
                     Regex.match?(~r/json\.loads/, code)  # Dynamic JSON parsing

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
      ~r/document\.write\([^)]*user/i, # document.write with user input
      ~r/insertAdjacentHTML\(/,       # insertAdjacentHTML
    ]
    
    # Check for potentially dangerous patterns that need escaping
    needs_escaping = Regex.match?(~r/\.innerHTML\s*=/, code) || 
                     Regex.match?(~r/\.outerHTML\s*=/, code)
    
    has_unsafe = Enum.any?(unsafe_patterns, fn pattern -> Regex.match?(pattern, code) end)
    
    # Check for explicit escaping/sanitization
    has_escaping = Regex.match?(~r/escape|sanitize|DOMPurify|textContent|innerText|createTextNode|React\.createElement/i, code)
    
    # Safe if:
    # 1. Has safe patterns OR escaping, AND
    # 2. No definitely unsafe patterns, AND
    # 3. If using innerHTML/outerHTML, must have escaping
    (has_safe || has_escaping) && !has_unsafe && (!needs_escaping || has_escaping)
  end
  
  def is_safe_pattern?(:code_injection, code, %{language: "javascript"}) do
    # Check for eval with literals or constants
    safe_patterns = [
      ~r/eval\(['"][\w\s\+\-\*\/\(\)]+['"]\)/,  # Eval with literal string
      ~r/eval\([A-Z_]+\)/,                       # Eval with constant
      ~r/new Function\(['"]return/,             # Safe Function constructor
    ]
    
    Enum.any?(safe_patterns, fn pattern -> Regex.match?(pattern, code) end)
  end
  
  def is_safe_pattern?(:command_injection, code, %{language: language}) when language in ["javascript", "python", "ruby", "php"] do
    # Check for safe command execution patterns
    safe_patterns = case language do
      "javascript" -> [
        ~r/execFile\(/,                  # execFile is safer than exec
        ~r/spawn\(['"][^'"]+['"]\s*,\s*\[/,  # spawn with array of args
        ~r/exec\(['"][^'"$`]+['"]\)\s*$/,    # exec with literal string only (no concat)
      ]
      "python" -> [
        ~r/subprocess\.run\(\[/,         # subprocess.run with list
        ~r/subprocess\.call\(\[/,        # subprocess.call with list
        ~r/os\.execv/,                   # os.execv (doesn't use shell)
        ~r/check=True/,                  # Explicit check flag
      ]
      "ruby" -> [
        ~r/system\(['"][^'"$`]+['"]\)/,  # system with literal string
        ~r/Open3\./,                     # Open3 is safer
      ]
      "php" -> [
        ~r/escapeshellcmd/,              # Command escaping
        ~r/escapeshellarg/,              # Argument escaping
        ~r/exec\(['"][^'"$`]+['"]\)/,    # exec with literal
      ]
    end
    
    # Check for unsafe patterns that override safe detection
    unsafe_patterns = [
      ~r/\+\s*user/,                   # String concatenation with user variables
      ~r/\$\{.*user/,                  # Template literals with user input
      ~r/\$\(/,                        # Command substitution
      ~r/`.*\$/,                       # Backticks with variables
      ~r/req\./,                       # Request data
      ~r/params\[/,                    # Parameters array access
      ~r/shell\s*:\s*true/,            # shell: true option
      ~r/shell=True/,                  # Python shell=True
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
      ~r/path\.normalize\(/,           # path.normalize is always safe
      ~r/path\.resolve\(/,             # path.resolve is safe
      ~r/Path\([^)]*\)\.resolve\(/,    # pathlib.Path().resolve() is safe
      ~r/basename\(/,                  # Using basename (PHP) is safe
      ~r/realpath\(/,                  # realpath (PHP) is safe
    ]
    
    # These patterns are conditionally safe (only with constants/literals)
    conditionally_safe_patterns = [
      ~r/path\.join\(__dirname/,           # path.join with __dirname
      ~r/path\.join\([^,]*['"][^'"]*['"]/, # path.join with literals
      ~r/os\.path\.join\([A-Z_]+/,         # os.path.join with constants like BASE_DIR
      ~r/os\.path\.join\(['"][^'"]*['"]/, # os.path.join with literals only
      ~r/Rails\.root\.join\(['"][^'"]*['"]/, # Rails.root.join with literals
      ~r/pathlib\.Path/,                   # pathlib.Path is generally safe
    ]
    
    # Check for definitely unsafe patterns - but exclude safe built-ins
    definitely_unsafe = [
      ~r/req\.(query|body|params)/,    # request data
      ~r/params\[/,                    # params hash
      ~r/\$_GET/,                      # PHP GET params
      ~r/\$_POST/,                     # PHP POST params
      ~r/\.\.\//,                      # Path traversal
      ~r/user_?[pP]ath/,                # user_path or userPath variables
      ~r/user_?[fF]ile/,                # user_file or userFile variables
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
      ~r/axios\.get\(['"][^'"]+['"]\)/,        # Literal URL (JS)
      ~r/fetch\(['"][^'"]+['"]\)/,             # Literal URL (JS)
      ~r/fetch\(`\$\{[A-Z_]+\}/,               # Template with constants (JS)
      ~r/\$\{[A-Z_]+\}/,                        # Using constants like ${API_BASE}
      ~r/process\.env\.[A-Z_]+/,               # Environment variables
      ~r/requests\.get\(f['"]\{[A-Z_]+\}/,     # Python f-string with constants
      ~r/urlopen\(['"][^'"]+['"]\)/,           # Python literal URL
      ~r/localhost|127\.0\.0\.1/,              # Localhost URLs
    ]

    # Check for unsafe patterns with user input
    unsafe_patterns = [
      ~r/req\.\w+/,                    # Request data
      ~r/params\[/,                     # Parameters
      ~r/body\./,                       # Body data
      ~r/query\./,                      # Query data
      ~r/user[A-Z]/,                    # User input (camelCase)
      ~r/user_/,                        # User input (snake_case)
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
      ~r/process\.env\.[A-Z_]+/,               # process.env.API_KEY
      ~r/import\.meta\.env\.[A-Z_]+/,          # Vite: import.meta.env.VITE_API_KEY

      # Environment variables - Python
      ~r/os\.environ\[/,                       # os.environ['KEY']
      ~r/os\.getenv\(/,                        # os.getenv('KEY')
      ~r/environ\.get\(/,                      # environ.get('KEY')

      # Environment variables - Ruby
      ~r/ENV\[/,                               # ENV['KEY']
      ~r/ENV\.fetch\(/,                        # ENV.fetch('KEY')

      # Environment variables - PHP
      ~r/\$_ENV\[/,                            # $_ENV['KEY']
      ~r/getenv\(/,                            # getenv('KEY')
      ~r/\$_SERVER\[['"].*KEY/,                # $_SERVER['API_KEY']

      # Environment variables - Go
      ~r/os\.Getenv\(/,                        # os.Getenv("KEY")
      ~r/os\.LookupEnv\(/,                     # os.LookupEnv("KEY")

      # Environment variables - Java
      ~r/System\.getenv\(/,                    # System.getenv("KEY")
      ~r/System\.getProperty\(/,               # System.getProperty("key")

      # Environment variables - Rust
      ~r/env::var\(/,                          # env::var("KEY")
      ~r/std::env::var\(/,                     # std::env::var("KEY")

      # Environment variables - Elixir
      ~r/System\.get_env\(/,                   # System.get_env("KEY")
      ~r/System\.fetch_env!\(/,                # System.fetch_env!("KEY")

      # Config files - JavaScript/TypeScript
      ~r/config\.get\(/,                       # config.get('key')
      ~r/process\.env\[/,                      # process.env[key]
      ~r/require\(['"]config['"]\)/,           # require('config')

      # Config files - Python
      ~r/settings\.[A-Z_]+/,                   # Django: settings.SECRET_KEY
      ~r/config\[/,                            # config['key']
      ~r/ConfigParser/,                        # ConfigParser usage

      # Config files - Ruby
      ~r/Rails\.application\.credentials/,     # Rails credentials
      ~r/Rails\.application\.secrets/,         # Rails secrets
      ~r/Config\./,                            # Config gem

      # Config files - PHP
      ~r/config\(/,                           # Laravel: config('app.key')
      ~r/Config::get\(/,                       # Config::get('key')

      # Config files - Go
      ~r/viper\./,                             # Viper config
      ~r/godotenv/,                            # godotenv usage

      # Config files - Java
      ~r/Properties\(\)/,                      # Properties file
      ~r/@Value\(/,                            # Spring @Value
      ~r/application\.properties/,             # Spring properties

      # Config files - Rust
      ~r/Config::builder\(/,                   # config crate
      ~r/dotenv\(\)/,                          # dotenv usage

      # Config files - Elixir
      ~r/Application\.get_env\(/,              # Application.get_env()
      ~r/Application\.fetch_env!\(/,           # Application.fetch_env!()
      ~r/config :[\w]+,/,                      # config :app, key: value

      # Secret managers
      ~r/secretsManager\./,                    # AWS Secrets Manager
      ~r/SecretsManager/,                      # AWS SDK
      ~r/key_vault\./,                         # Azure Key Vault
      ~r/KeyVault/,                            # Azure SDK
      ~r/vault\./,                             # HashiCorp Vault
      ~r/SecretManager\./,                     # Google Secret Manager
      ~r/KMS\./,                               # AWS KMS
      ~r/ParameterStore/,                      # AWS Parameter Store

      # Framework-specific secure patterns
      ~r/Rails\.application\.secrets/,         # Rails secrets
      ~r/Keyring\./,                           # Python keyring
      ~r/keychain\./,                          # macOS Keychain
      ~r/credential_process/,                  # AWS credential process

      # Config loaders
      ~r/dotenv/,                              # dotenv library
      ~r/decouple/,                            # python-decouple
      ~r/environs/,                            # environs library
    ]

    # Check for unsafe patterns - hardcoded secrets
    unsafe_patterns = [
      # Common secret patterns
      ~r/['"][a-zA-Z0-9]{32,}['"]/,           # Long alphanumeric strings
      ~r/sk[-_][a-zA-Z0-9]+/,                 # Stripe-like keys
      ~r/AKIA[A-Z0-9]+/,                      # AWS access keys
      ~r/ghp_[a-zA-Z0-9]+/,                   # GitHub personal tokens
      ~r/glpat-[a-zA-Z0-9]+/,                 # GitLab tokens
      ~r/['"]Bearer\s+[a-zA-Z0-9\-._]+['"]/,  # Bearer tokens

      # Password patterns
      ~r/password\s*[:=]\s*['"][^'"]+['"]/,   # password = "something"
      ~r/passwd\s*[:=]\s*['"][^'"]+['"]/,     # passwd = "something"
      ~r/pwd\s*[:=]\s*['"][^'"]+['"]/,        # pwd = "something"

      # API key patterns
      ~r/api_?key\s*[:=]\s*['"][^'"]+['"]/i,  # api_key = "something"
      ~r/apikey\s*[:=]\s*['"][^'"]+['"]/i,    # apikey = "something"
      ~r/token\s*[:=]\s*['"][^'"]+['"]/,      # token = "something"
      ~r/secret\s*[:=]\s*['"][^'"]+['"]/,     # secret = "something"
    ]

    has_safe = Enum.any?(safe_patterns, fn pattern -> Regex.match?(pattern, code) end)
    has_unsafe = Enum.any?(unsafe_patterns, fn pattern -> Regex.match?(pattern, code) end)

    # It's safe if it uses safe patterns and doesn't have hardcoded values
    has_safe && !has_unsafe
  end

  # Default case - not recognized as safe
  def is_safe_pattern?(_vulnerability_type, _code, _context), do: false
  
  # Private helper functions
  
  defp get_timing_safe_patterns("javascript"), do: [
    ~r/===\s+[A-Z][A-Z_]+/,              # Constant comparison
    ~r/===\s+\w+\.[A-Z]/,                # Module constant
    ~r/\.code\s*===\s*DOMException\./,  # DOMException constants
    ~r/\.status\s*===\s*\d+/,           # HTTP status codes
    ~r/===\s*\d+/,                       # Numeric literal comparison
    ~r/!==\s*\d+/,                       # Numeric literal not-equal
    ~r/\w+\s*===\s*\d+/,                 # Any variable compared to number
  ]
  defp get_timing_safe_patterns("python"), do: [
    ~r/==\s+[A-Z][A-Z_]+/,               # Constant comparison
    ~r/==\s+\w+\.[A-Z]/,                 # Module constant
    ~r/\.status_code\s*==\s*\d+/,       # HTTP status codes
  ]
  defp get_timing_safe_patterns("ruby"), do: [
    ~r/==\s+[A-Z][A-Z_]+/,               # Constant comparison
    ~r/==\s+::\w+/,                      # Module constant
    ~r/\.status\s*==\s*\d+/,             # HTTP status codes
  ]
  defp get_timing_safe_patterns("php"), do: [
    ~r/===\s+[A-Z][A-Z_]+/,              # Constant comparison
    ~r/===\s+\w+::[A-Z]/,                # Class constant
    ~r/->getStatusCode\(\)\s*===\s*\d+/, # HTTP status codes
  ]
  defp get_timing_safe_patterns(_), do: []

  defp get_sql_unsafe_patterns("javascript"), do: [
    ~r/SELECT.*\+\s*\w+/i,               # SELECT with concatenation
    ~r/WHERE.*\+\s*\w+/i,                # WHERE with concatenation  
    ~r/VALUES.*\+\s*\w+/i,               # VALUES with concatenation
    ~r/FROM\s+['"]?\s*\+\s*/i,          # FROM with concatenation
    ~r/query\([^,]*\+[^,]*\)/,           # query() with concatenation
    ~r/password\s*===\s*\w+Password/,    # Timing attack vulnerability on same line
    ~r/apiKey\s*===/,                    # API key comparison on same line
    ~r/token\s*===/,                     # Token comparison on same line
  ]
  defp get_sql_unsafe_patterns("python"), do: [
    ~r/SELECT.*["']\s*%\s*\w+/i,         # SELECT with % formatting (not parameterized)
    ~r/WHERE.*["']\s*%\s*\w+/i,          # WHERE with % formatting (not parameterized)
    ~r/VALUES.*["']\s*%\s*\w+/i,         # VALUES with % formatting (not parameterized)
    ~r/execute\([^,]+["']\s*%\s*[^,)]+\)$/,  # execute() with % formatting without params
    ~r/SELECT.*f["']/i,                  # f-string in SQL
    ~r/WHERE.*f["']/i,                   # f-string in WHERE
  ]
  defp get_sql_unsafe_patterns("ruby"), do: [
    ~r/SELECT.*#\{/i,                    # SELECT with interpolation
    ~r/WHERE.*#\{/i,                     # WHERE with interpolation
    ~r/VALUES.*#\{/i,                    # VALUES with interpolation
    ~r/exec\([^,]*\+[^,]*\)/,            # exec() with concatenation
  ]
  defp get_sql_unsafe_patterns("php"), do: [
    ~r/SELECT.*\.\s*\$/i,                # SELECT with concatenation
    ~r/WHERE.*\.\s*\$/i,                 # WHERE with concatenation
    ~r/VALUES.*\.\s*\$/i,                # VALUES with concatenation
    ~r/query\([^,]*\.\s*\$/,             # query() with concatenation
  ]
  defp get_sql_unsafe_patterns(_), do: []

  defp get_sql_safe_patterns("javascript"), do: [
    ~r/\$\d+/,                            # PostgreSQL params ($1, $2)
    ~r/\?\s*[,\)]/,                       # MySQL params (?)
    ~r/:\w+/,                             # Named params (:id, :name)
    ~r/\.query\([^,]+,\s*\[/,            # Parameterized query with array
    ~r/\.prepare\(/,                      # Prepared statements
  ]
  defp get_sql_safe_patterns("python"), do: [
    ~r/\.execute\([^,]+,\s*[\[\(]/,      # Parameterized execute with params
    ~r/\.executemany\([^,]+,\s*[\[\(]/,  # Parameterized executemany
    ~r/\?\s*[,\)]/,                       # SQLite params when not using %
    ~r/:\w+/,                             # Named params
    ~r/\.objects\.filter\(/,              # Django ORM filter
    ~r/\.objects\.get\(/,                 # Django ORM get
    ~r/\.objects\.all\(/,                 # Django ORM all
  ]
  defp get_sql_safe_patterns("ruby"), do: [
    ~r/\?\s*[,\)]/,                       # Placeholder params
    ~r/:\w+/,                             # Named params
    ~r/\.where\([^,]+,\s*[\[\{]/,        # Rails where with params
  ]
  defp get_sql_safe_patterns("php"), do: [
    ~r/\?\s*[,\)]/,                       # PDO placeholders
    ~r/:\w+/,                             # PDO named params
    ~r/->prepare\(/,                      # Prepared statements
    ~r/->bind_param\(/,                   # mysqli bind
  ]
  defp get_sql_safe_patterns(_), do: []

  defp get_nosql_safe_patterns("javascript"), do: [
    ~r/\.find\(\{[^$]*\}\)/,             # No $where
    ~r/\.findOne\(\{[^$]*\}\)/,          # No $where
    ~r/\.findById\(/,                    # Safe findById
    ~r/\.updateOne\(\{[^$]*\}\)/,        # No $where in update
  ]
  defp get_nosql_safe_patterns("python"), do: [
    ~r/\.find\(\{[^$]*\}\)/,             # No $where
    ~r/\.find_one\(\{[^$]*\}\)/,         # No $where
  ]
  defp get_nosql_safe_patterns(_), do: []
  
  defp get_xss_safe_patterns("javascript"), do: [
    ~r/\.textContent\s*=/,               # Safe text content
    ~r/\.innerText\s*=/,                # Safe inner text
    ~r/\.render\(/,                      # Template rendering (usually safe)
    ~r/escape\(/,                        # Escaping function
    ~r/sanitize\(/,                      # Sanitization
    ~r/\$\([^)]+\)\.text\(/,            # jQuery .text() method
    ~r/createTextNode\(/,                # DOM createTextNode
    ~r/React\.createElement\(/,          # React createElement is safe by default
  ]
  defp get_xss_safe_patterns("python"), do: [
    ~r/escape\(/,                        # Escaping
    ~r/markup\.escape\(/,                # Markup escape
    ~r/\.render\(/,                      # Template rendering
  ]
  defp get_xss_safe_patterns("ruby"), do: [
    ~r/html_safe/,                       # Rails html_safe
    ~r/escape_html\(/,                   # HTML escaping
    ~r/h\(/,                             # Rails h() helper
  ]
  defp get_xss_safe_patterns("php"), do: [
    ~r/htmlspecialchars\(/,              # PHP escaping
    ~r/htmlentities\(/,                  # PHP entities
    ~r/filter_var\(/,                    # Input filtering
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
      0.1  # 90% reduction for safe patterns
    else
      1.0  # No adjustment for potentially unsafe patterns
    end
  end
end