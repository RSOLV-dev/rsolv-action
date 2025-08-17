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
  
  defp get_timing_safe_patterns("javascript"), do: [
    ~r/===\s+[A-Z][A-Z_]+/,              # Constant comparison
    ~r/===\s+\w+\.[A-Z]/,                # Module constant
    ~r/\.code\s*===\s*DOMException\./,  # DOMException constants
    ~r/\.status\s*===\s*\d+/,           # HTTP status codes
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

  defp get_sql_safe_patterns("javascript"), do: [
    ~r/\$\d+/,                            # PostgreSQL params ($1, $2)
    ~r/\?\s*[,\)]/,                       # MySQL params (?)
    ~r/:\w+/,                             # Named params (:id, :name)
    ~r/\.query\([^,]+,\s*\[/,            # Parameterized query with array
    ~r/\.prepare\(/,                      # Prepared statements
  ]
  defp get_sql_safe_patterns("python"), do: [
    ~r/%s/,                               # Python DB-API params
    ~r/\?\s*[,\)]/,                       # SQLite params
    ~r/:\w+/,                             # Named params
    ~r/\.execute\([^,]+,\s*[\[\(]/,      # Parameterized execute
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
    ~r/\.updateOne\(\{[^$]*\}/,          # No $where in update
  ]
  defp get_nosql_safe_patterns("python"), do: [
    ~r/\.find\(\{[^$]*\}\)/,             # No $where
    ~r/\.find_one\(\{[^$]*\}\)/,         # No $where
  ]
  defp get_nosql_safe_patterns(_), do: []

  def is_safe_pattern?(:sql_injection, code, %{language: language}) do
    patterns = get_sql_safe_patterns(language)
    safe = Enum.any?(patterns, fn pattern -> Regex.match?(pattern, code) end)
    
    # Check for unsafe concatenation that overrides safe patterns
    unsafe_patterns = [
      ~r/\+\s*['"]?\s*\w+/,           # String concatenation
      ~r/WHERE.*\+\s*/i,               # WHERE clause concatenation
      ~r/VALUES.*\+\s*/i,              # VALUES concatenation
    ]
    
    safe && !Enum.any?(unsafe_patterns, fn pattern -> Regex.match?(pattern, code) end)
  end
  
  def is_safe_pattern?(:nosql_injection, code, %{language: "javascript"}) do
    patterns = get_nosql_safe_patterns("javascript")
    safe = Enum.any?(patterns, fn pattern -> Regex.match?(pattern, code) end)
    
    # If it contains $where, it's definitely unsafe
    has_where = Regex.match?(~r/\$where/, code)
    
    # For other patterns, check if they're in a safe context
    safe && !has_where
  end
  
  def is_safe_pattern?(:nosql_injection, _code, _context), do: false
  
  defp get_xss_safe_patterns("javascript"), do: [
    ~r/\.textContent\s*=/,               # Safe text content
    ~r/\.innerText\s*=/,                # Safe inner text
    ~r/\.render\(/,                      # Template rendering (usually safe)
    ~r/escape\(/,                        # Escaping function
    ~r/sanitize\(/,                      # Sanitization
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

  def is_safe_pattern?(:xss, code, %{language: language}) do
    patterns = get_xss_safe_patterns(language)
    safe = Enum.any?(patterns, fn pattern -> Regex.match?(pattern, code) end)
    
    # Check for dangerous HTML insertion
    unsafe_patterns = [
      ~r/\.innerHTML\s*=/,            # innerHTML assignment
      ~r/document\.write\(/,          # document.write
      ~r/\.outerHTML\s*=/,            # outerHTML assignment
      ~r/insertAdjacentHTML\(/,       # insertAdjacentHTML
    ]
    
    # Only safe if it has escaping AND no direct HTML insertion
    safe && !Enum.any?(unsafe_patterns, fn pattern -> Regex.match?(pattern, code) end)
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
  
  def is_safe_pattern?(:command_injection, code, %{language: "javascript"}) do
    # Check for safe command execution patterns
    safe_patterns = [
      ~r/execFile\(/,                  # execFile is safer than exec
      ~r/spawn\(['"][^'"]+['"]\s*,\s*\[/,  # spawn with array of args
      ~r/exec\(['"][^'"$`]+['"]\)\s*$/,    # exec with literal string only (no concat)
    ]
    
    # Check for unsafe patterns that override safe detection
    unsafe_patterns = [
      ~r/exec\([^)]*\+/,               # exec with string concatenation
      ~r/exec\([^)]*\$\{/,             # exec with template literals
      ~r/exec\([^)]*req\./,            # exec with request data
      ~r/exec\([^)]*params/,           # exec with params
      ~r/shell\s*:\s*true/,            # shell: true option
    ]
    
    has_safe = Enum.any?(safe_patterns, fn pattern -> Regex.match?(pattern, code) end)
    has_unsafe = Enum.any?(unsafe_patterns, fn pattern -> Regex.match?(pattern, code) end)
    
    # Only safe if it matches safe patterns AND doesn't match unsafe patterns
    has_safe && !has_unsafe
  end
  
  def is_safe_pattern?(:path_traversal, code, %{language: _language}) do
    # Check for path sanitization
    safe_patterns = [
      ~r/path\.join\(/,                # path.join
      ~r/path\.resolve\(/,             # path.resolve
      ~r/\.replace\(\/\.\.\//,         # Removing ../
      ~r/basename\(/,                  # Using basename
      ~r/normalize\(/,                 # Path normalization
    ]
    
    Enum.any?(safe_patterns, fn pattern -> Regex.match?(pattern, code) end)
  end
  
  def is_safe_pattern?(:ssrf, code, %{language: _language}) do
    # Check for safe URL patterns (constants, not user input)
    safe_patterns = [
      ~r/axios\.get\(['"][^'"]+['"]\)/,        # Literal URL
      ~r/fetch\(['"][^'"]+['"]\)/,             # Literal URL
      ~r/\$\{[A-Z_]+\}/,                        # Using constants like ${API_BASE}
      ~r/process\.env\.[A-Z_]+/,               # Environment variables
    ]
    
    # Check for unsafe patterns with user input
    unsafe_patterns = [
      ~r/req\.\w+/,                    # Request data
      ~r/params/,                       # Parameters
      ~r/body\./,                       # Body data
      ~r/query\./,                      # Query data
      ~r/userInput/,                    # Obvious user input
      ~r/userProvidedUrl/,              # Obvious user input
    ]
    
    has_safe = Enum.any?(safe_patterns, fn pattern -> Regex.match?(pattern, code) end)
    has_unsafe = Enum.any?(unsafe_patterns, fn pattern -> Regex.match?(pattern, code) end)
    
    # Only safe if it doesn't have user input
    has_safe && !has_unsafe
  end
  
  # Default case - not recognized as safe
  def is_safe_pattern?(_vulnerability_type, _code, _context), do: false
  
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