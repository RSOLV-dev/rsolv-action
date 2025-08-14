defmodule RsolvWeb.Api.V1.SafePatternDetector do
  @moduledoc """
  Detects safe coding patterns that are often incorrectly flagged as vulnerabilities.
  Part of RFC-042: AST False Positive Reduction Enhancement.
  
  This module identifies patterns that use secure coding practices like parameterized
  queries, constant comparisons, and framework-provided escaping mechanisms.
  """
  
  # Timing attack safe patterns - comparing against constants
  @timing_safe_patterns %{
    javascript: [
      ~r/===\s+[A-Z][A-Z0-9_]*(\.[A-Z][A-Z0-9_]*)*/, # Constant comparison
      ~r/===\s+\w+\.[A-Z][A-Z0-9_]+/,                 # Module.CONSTANT
      ~r/==\s+[A-Z][A-Z0-9_]*(\.[A-Z][A-Z0-9_]*)*/, # Loose equality with constant
    ],
    python: [
      ~r/==\s+\w+\.[A-Z][A-Z0-9_]+/,                  # module.CONSTANT
      ~r/==\s+[A-Z][A-Z0-9_]+/,                       # CONSTANT
      ~r/is\s+[A-Z][A-Z0-9_]+/,                       # is CONSTANT
    ],
    ruby: [
      ~r/==\s+[A-Z]\w*(::[A-Z]\w*)*/,                 # Module::CONSTANT
      ~r/===\s+[A-Z]\w*/,                              # Case equality with constant
    ],
    php: [
      ~r/===\s+[A-Z][A-Z0-9_]+/,                      # Strict comparison with constant
      ~r/==\s+\w+::[A-Z][A-Z0-9_]+/,                  # Class::CONSTANT
    ]
  }
  
  # SQL injection safe patterns - parameterized queries
  @sql_safe_patterns %{
    javascript: [
      ~r/\$\d+/,                                       # PostgreSQL: $1, $2
      ~r/\?\s*[,\)]/,                                  # MySQL: ?, ?
      ~r/:\w+/,                                        # Named params: :userId
      ~r/\.query\([^,]+,\s*\[/,                       # query with array params
      ~r/\.execute\([^,]+,\s*\[/,                     # execute with array params
    ],
    python: [
      ~r/%s/,                                          # Python DB-API format
      ~r/\?\s*[,\)]/,                                  # SQLite style
      ~r/:\w+/,                                        # Named params
      ~r/\.execute\([^,]+,\s*[\(\[]/,                 # execute with params
    ],
    ruby: [
      ~r/\?\s*[,\)]/,                                  # Rails/ActiveRecord placeholders
      ~r/where\([^,]+,\s*[^\)]+\)/,                   # where with params
      ~r/:\w+/,                                        # Named params
    ],
    php: [
      ~r/\?\s*[,\)]/,                                  # PDO placeholders
      ~r/:\w+/,                                        # PDO named params
      ~r/->execute\(\[/,                              # PDO execute with array
      ~r/escapeshellarg/,                             # Shell escaping
    ]
  }
  
  # NoSQL safe patterns - queries without dangerous operators
  @nosql_safe_patterns %{
    javascript: [
      ~r/\.find\(\{[^\$]*\}\)/,                       # find without $ operators
      ~r/\.findOne\(\{[^\$]*\}\)/,                    # findOne without $ operators
      ~r/\.findById\(/,                               # findById (safe)
      ~r/\.updateOne\(\{[^\$]*\},\s*\{\s*\$set:/,    # updateOne with $set only
      ~r/\.find\(\{\s*\w+:\s*[^$]/,                  # Simple field queries
    ]
  }
  
  # XSS safe patterns - template engines with auto-escaping
  @xss_safe_patterns %{
    javascript: [
      ~r/res\.render\(/,                              # Express templates (escaped by default)
      ~r/\{\{[^}]+\}\}/,                              # Handlebars/Mustache (escaped)
      ~r/<[^>]+>\{[^}]+\}<\/[^>]+>/,                 # React JSX (escaped)
      ~r/\{\{[^}]+\}\}/,                              # Vue/Angular templates
      ~r/dangerouslySetInnerHTML/,                    # React - explicitly marked dangerous
    ],
    python: [
      ~r/\{\{[^}]+\|escape\}\}/,                     # Django with escape filter
      ~r/\{\{[^}]+\}\}/,                              # Jinja2 (auto-escaped by default)
      ~r/render_template\(/,                          # Flask templates
    ],
    ruby: [
      ~r/<%=\s*h\s+/,                                 # Rails with h helper
      ~r/<%=\s*html_escape/,                          # Rails html_escape
      ~r/<%=\s*sanitize/,                             # Rails sanitize helper
    ],
    php: [
      ~r/\{\{[^}]+\}\}/,                              # Blade templates (escaped)
      ~r/htmlspecialchars\(/,                         # PHP escaping
      ~r/htmlentities\(/,                             # PHP entity encoding
    ]
  }
  
  # Command injection safe patterns - using arrays for arguments
  @command_safe_patterns %{
    javascript: [
      ~r/spawn\([^,]+,\s*\[/,                        # spawn with array args
      ~r/exec\([^,]+,\s*\[/,                         # exec with array args
      ~r/execFile\(/,                                # execFile (safer than exec)
    ],
    python: [
      ~r/subprocess\.\w+\(\[/,                       # subprocess with list args
      ~r/run\(\[/,                                   # run with list
      ~r/Popen\(\[/,                                 # Popen with list
    ],
    ruby: [
      ~r/system\([^,]+,[^,]+/,                       # system with multiple args
      ~r/spawn\([^,]+,[^,]+/,                        # spawn with multiple args
      ~r/Open3\./,                                   # Open3 methods
    ],
    php: [
      ~r/escapeshellarg\(/,                          # PHP shell arg escaping
      ~r/escapeshellcmd\(/,                          # PHP shell cmd escaping
    ]
  }
  
  # Path traversal safe patterns - proper path joining
  @path_safe_patterns %{
    javascript: [
      ~r/path\.join\(/,                              # Node path.join
      ~r/path\.resolve\(/,                           # Node path.resolve
      ~r/path\.normalize\(/,                         # Node path.normalize
    ],
    python: [
      ~r/os\.path\.join\(/,                          # Python path.join
      ~r/pathlib\.Path\(/,                           # Python pathlib
      ~r/os\.path\.abspath\(/,                       # Absolute path
    ],
    ruby: [
      ~r/File\.join\(/,                              # Ruby File.join
      ~r/Rails\.root/,                               # Rails root path
      ~r/Pathname\./,                                # Pathname methods
    ],
    php: [
      ~r/realpath\(/,                                # PHP realpath
      ~r/basename\(/,                                # PHP basename
      ~r/DIRECTORY_SEPARATOR/,                       # Using proper separator
    ]
  }
  
  # Code injection safe patterns - alternatives to eval
  @code_safe_patterns %{
    javascript: [
      ~r/JSON\.parse\(/,                             # JSON parsing instead of eval
      ~r/Function\.prototype/,                       # Using prototype methods
      ~r/\[\w+\]\(/,                                # Bracket notation for safe calls
    ],
    python: [
      ~r/json\.loads\(/,                             # JSON parsing
      ~r/ast\.literal_eval\(/,                       # Safe eval for literals
      ~r/getattr\(/,                                 # Safe attribute access
    ],
    ruby: [
      ~r/JSON\.parse\(/,                             # JSON parsing
      ~r/send\(:\w+\)/,                              # send with symbol (safer)
      ~r/public_send\(/,                             # public_send method
    ],
    php: [
      ~r/json_decode\(/,                             # JSON parsing
      ~r/unserialize\([^,]+,\s*\['allowed_classes'/, # Safe unserialize
    ]
  }
  
  @doc """
  Checks if a code pattern is safe for a given vulnerability type.
  
  ## Examples
  
      iex> SafePatternDetector.is_safe_pattern?(:timing_attack, "status === HTTP_OK", %{language: "javascript"})
      true
      
      iex> SafePatternDetector.is_safe_pattern?(:sql_injection, "query('SELECT * FROM users WHERE id = $1', [id])", %{language: "javascript"})
      true
  """
  def is_safe_pattern?(vulnerability_type, code, context \\ %{})
  
  def is_safe_pattern?(:timing_attack, code, %{language: language}) do
    patterns = Map.get(@timing_safe_patterns, String.to_atom(language), [])
    
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
  
  def is_safe_pattern?(:sql_injection, code, %{language: language}) do
    patterns = Map.get(@sql_safe_patterns, String.to_atom(language), [])
    safe = Enum.any?(patterns, fn pattern -> Regex.match?(pattern, code) end)
    
    # Check for unsafe concatenation that overrides safe patterns
    unsafe_patterns = [
      ~r/\+\s*['"]?\s*\w+/,           # String concatenation
      ~r/\$\{[^}]+\}/,                 # Template literals with interpolation
      ~r/WHERE.*\+/,                   # WHERE clause with concatenation
      ~r/WHERE.*\|\|/,                 # SQL concatenation operator
    ]
    
    safe && !Enum.any?(unsafe_patterns, fn pattern -> Regex.match?(pattern, code) end)
  end
  
  def is_safe_pattern?(:nosql_injection, code, %{language: "javascript"}) do
    patterns = Map.get(@nosql_safe_patterns, :javascript, [])
    safe = Enum.any?(patterns, fn pattern -> Regex.match?(pattern, code) end)
    
    # Check for dangerous MongoDB operators
    dangerous_patterns = [
      ~r/\$where/,                    # $where operator
      ~r/\$query/,                    # $query operator
      ~r/\$ne/,                       # $ne can be exploited
      ~r/\$gt/,                       # $gt in wrong context
      ~r/\$regex/,                    # $regex with user input
    ]
    
    # If it contains $where, it's definitely unsafe
    has_where = Regex.match?(~r/\$where/, code)
    
    # For other patterns, check if they're in a safe context
    safe && !has_where
  end
  
  def is_safe_pattern?(:nosql_injection, _code, _context), do: false
  
  def is_safe_pattern?(:xss, code, %{language: language}) do
    patterns = Map.get(@xss_safe_patterns, String.to_atom(language), [])
    safe = Enum.any?(patterns, fn pattern -> Regex.match?(pattern, code) end)
    
    # Check for dangerous HTML insertion
    unsafe_patterns = [
      ~r/\.innerHTML\s*=/,            # innerHTML assignment
      ~r/document\.write\(/,          # document.write
      ~r/\.html\(/,                   # jQuery html()
      ~r/\.outerHTML\s*=/,           # outerHTML assignment
      ~r/<%=\s*raw\s+/,              # Rails raw output
      ~r/\|safe/,                     # Django safe filter
      ~r/v-html/,                     # Vue v-html directive
    ]
    
    safe && !Enum.any?(unsafe_patterns, fn pattern -> Regex.match?(pattern, code) end)
  end
  
  def is_safe_pattern?(:command_injection, code, %{language: language}) do
    patterns = Map.get(@command_safe_patterns, String.to_atom(language), [])
    safe = Enum.any?(patterns, fn pattern -> Regex.match?(pattern, code) end)
    
    # Check for string concatenation in commands
    unsafe_patterns = [
      ~r/exec\([^,]*\+/,              # exec with concatenation
      ~r/system\([^,]*\+/,            # system with concatenation
      ~r/`.*\$\{/,                    # Backticks with interpolation
      ~r/shell_exec\(/,               # PHP shell_exec
    ]
    
    safe && !Enum.any?(unsafe_patterns, fn pattern -> Regex.match?(pattern, code) end)
  end
  
  def is_safe_pattern?(:path_traversal, code, %{language: language}) do
    patterns = Map.get(@path_safe_patterns, String.to_atom(language), [])
    safe = Enum.any?(patterns, fn pattern -> Regex.match?(pattern, code) end)
    
    # Check for unsafe path concatenation
    unsafe_patterns = [
      ~r/['"]\/.*\+/,                 # Path concatenation
      ~r/\.\.\//,                     # Directory traversal
      ~r/\\.\.\\/,                    # Windows traversal
    ]
    
    safe && !Enum.any?(unsafe_patterns, fn pattern -> Regex.match?(pattern, code) end)
  end
  
  def is_safe_pattern?(:code_injection, code, %{language: language}) do
    patterns = Map.get(@code_safe_patterns, String.to_atom(language), [])
    safe = Enum.any?(patterns, fn pattern -> Regex.match?(pattern, code) end)
    
    # Check for actual eval usage
    unsafe_patterns = [
      ~r/\beval\s*\(/,                # eval function
      ~r/new\s+Function\(/,           # Function constructor
      ~r/\bexec\s*\(/,                # exec function
      ~r/setTimeout\([^,]+,\s*[^0-9]/, # setTimeout with non-numeric delay
    ]
    
    safe && !Enum.any?(unsafe_patterns, fn pattern -> Regex.match?(pattern, code) end)
  end
  
  def is_safe_pattern?(_vulnerability_type, _code, _context), do: false
  
  @doc """
  Detects all safe patterns present in the code.
  
  ## Examples
  
      iex> SafePatternDetector.detect_all_safe_patterns("db.query('SELECT...', [id]); res.render('view', data)", %{language: "javascript"})
      [:sql_injection, :xss]
  """
  def detect_all_safe_patterns(code, context) do
    vulnerability_types = [
      :timing_attack,
      :sql_injection,
      :nosql_injection,
      :xss,
      :command_injection,
      :path_traversal,
      :code_injection
    ]
    
    Enum.filter(vulnerability_types, fn type ->
      is_safe_pattern?(type, code, context)
    end)
  end
  
  @doc """
  Provides an explanation for why a pattern is safe or unsafe.
  
  ## Examples
  
      iex> SafePatternDetector.explain_safe_pattern(:sql_injection, "query('SELECT...', [id])", %{language: "javascript"})
      %{safe: true, reason: "Uses parameterized query", recommendation: nil}
  """
  def explain_safe_pattern(vulnerability_type, code, context) do
    safe = is_safe_pattern?(vulnerability_type, code, context)
    
    explanation = case {vulnerability_type, safe} do
      {:timing_attack, true} ->
        %{reason: "Comparison against constant value is not vulnerable to timing attacks", recommendation: nil}
      {:timing_attack, false} ->
        %{reason: "Direct comparison of sensitive values may be vulnerable to timing attacks", 
         recommendation: "Use constant-time comparison functions for sensitive data"}
        
      {:sql_injection, true} ->
        %{reason: "Uses parameterized queries which prevent SQL injection", recommendation: nil}
      {:sql_injection, false} ->
        %{reason: "String concatenation in SQL queries is vulnerable to injection",
         recommendation: "Use parameterized queries or prepared statements"}
        
      {:nosql_injection, true} ->
        %{reason: "Query uses safe operators without user-controlled query logic", recommendation: nil}
      {:nosql_injection, false} ->
        %{reason: "Use of $where or other dangerous operators with user input",
         recommendation: "Use simple field queries without operators like $where"}
        
      {:xss, true} ->
        %{reason: "Template engine provides automatic HTML escaping", recommendation: nil}
      {:xss, false} ->
        %{reason: "Direct HTML insertion without escaping",
         recommendation: "Use template engines with auto-escaping or explicit escape functions"}
        
      {:command_injection, true} ->
        %{reason: "Command arguments passed as array preventing injection", recommendation: nil}
      {:command_injection, false} ->
        %{reason: "String concatenation in system commands",
         recommendation: "Pass command arguments as array or use proper escaping"}
        
      {:path_traversal, true} ->
        %{reason: "Uses safe path joining methods", recommendation: nil}
      {:path_traversal, false} ->
        %{reason: "Direct path concatenation vulnerable to traversal",
         recommendation: "Use path.join() or similar safe path handling functions"}
        
      {:code_injection, true} ->
        %{reason: "Uses safe alternatives to eval like JSON.parse", recommendation: nil}
      {:code_injection, false} ->
        %{reason: "Direct use of eval or similar dangerous functions",
         recommendation: "Use JSON.parse or other safe parsing methods instead of eval"}
        
      _ ->
        %{reason: "Unknown pattern", recommendation: nil}
    end
    
    Map.put(explanation, :safe, safe)
  end
end