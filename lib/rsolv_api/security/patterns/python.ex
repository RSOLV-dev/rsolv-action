defmodule RsolvApi.Security.Patterns.Python do
  @moduledoc """
  Python security patterns for detecting vulnerabilities.
  
  This module contains 12 security patterns specifically designed for Python
  code. Each pattern includes detection rules, test cases, and educational
  documentation.
  """
  
  alias RsolvApi.Security.Pattern
  
  @doc """
  Returns all Python security patterns.
  
  ## Examples
  
      iex> patterns = RsolvApi.Security.Patterns.Python.all()
      iex> length(patterns)
      12
      iex> Enum.all?(patterns, &match?(%Pattern{}, &1))
      true
  """
  def all do
    [
      sql_injection_format(),
      sql_injection_fstring(),
      sql_injection_concat(),
      command_injection_os_system(),
      command_injection_subprocess_shell(),
      unsafe_pickle(),
      unsafe_eval(),
      path_traversal_open(),
      weak_hash_md5(),
      weak_hash_sha1(),
      debug_true(),
      unsafe_yaml_load()
    ]
  end
  
  @doc """
  SQL Injection via string formatting pattern.
  
  Detects SQL queries using % string formatting with user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Python.sql_injection_format()
      iex> pattern.id
      "python-sql-injection-format"
      iex> pattern.severity
      :high
      
  ## Detection Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Python.sql_injection_format()
      iex> vulnerable = ~S|cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      iex> safe = ~S|cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))|
      iex> Regex.match?(pattern.regex, safe)
      false
  """
  def sql_injection_format do
    %Pattern{
      id: "python-sql-injection-format",
      name: "SQL Injection via String Formatting",
      description: "Using % string formatting in SQL queries can lead to SQL injection",
      type: :sql_injection,
      severity: :high,
      languages: ["python"],
      regex: ~r/execute\s*\(\s*["'`].*%[sdf].*["'`]\s*%/,
      default_tier: :protected,
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation: "Use parameterized queries with execute() method parameters: cursor.execute(query, (param,))",
      test_cases: %{
        vulnerable: [
          ~S|cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)|,
          ~S|db.execute("DELETE FROM posts WHERE author = '%s'" % username)|,
          ~S|conn.execute("UPDATE accounts SET balance = %s WHERE id = %s" % (amount, account_id))|
        ],
        safe: [
          ~S|cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))|,
          ~S|db.execute("DELETE FROM posts WHERE author = %s", [username])|,
          ~S|conn.execute("UPDATE accounts SET balance = %s WHERE id = %s", (amount, account_id))|
        ]
      }
    }
  end
  
  @doc """
  SQL Injection via f-string formatting pattern.
  
  Detects SQL queries using f-strings with user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Python.sql_injection_fstring()
      iex> vulnerable = ~S|cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def sql_injection_fstring do
    %Pattern{
      id: "python-sql-injection-fstring",
      name: "SQL Injection via F-String Formatting",
      description: "Using f-strings in SQL queries can lead to SQL injection",
      type: :sql_injection,
      severity: :high,
      languages: ["python"],
      regex: ~r/execute\s*\(\s*f["'`].*\{.*\}.*["'`]/,
      default_tier: :protected,
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation: "Use parameterized queries instead of f-string formatting",
      test_cases: %{
        vulnerable: [
          ~S|cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")|,
          ~S|db.execute(f"DELETE FROM posts WHERE id = {post_id}")|,
          ~S|conn.execute(f"UPDATE users SET email = '{email}' WHERE id = {user_id}")|
        ],
        safe: [
          ~S|cursor.execute("SELECT * FROM users WHERE name = %s", (name,))|,
          ~S|db.execute("DELETE FROM posts WHERE id = ?", [post_id])|,
          ~S|conn.execute("UPDATE users SET email = ? WHERE id = ?", (email, user_id))|
        ]
      }
    }
  end
  
  @doc """
  SQL Injection via string concatenation pattern.
  
  Detects SQL queries built using string concatenation.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Python.sql_injection_concat()
      iex> vulnerable = ~S|cursor.execute("SELECT * FROM users WHERE id = " + user_id)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def sql_injection_concat do
    %Pattern{
      id: "python-sql-injection-concat",
      name: "SQL Injection via String Concatenation",
      description: "String concatenation in SQL queries can lead to SQL injection",
      type: :sql_injection,
      severity: :high,
      languages: ["python"],
      regex: ~r/(?:execute\s*\(\s*["'`].*["'`]\s*\+|["'`].*(?:SELECT|DELETE|UPDATE|INSERT).*["'`]\s*\+.*execute)/i,
      default_tier: :protected,
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation: "Use parameterized queries with execute() method parameters",
      test_cases: %{
        vulnerable: [
          ~S|cursor.execute("SELECT * FROM users WHERE id = " + user_id)|,
          ~S|db.execute("DELETE FROM posts WHERE author = '" + username + "'")|,
          ~S|query = "SELECT * FROM accounts WHERE id = " + str(account_id); cursor.execute(query)|
        ],
        safe: [
          ~S|cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))|,
          ~S|db.execute("DELETE FROM posts WHERE author = %s", [username])|,
          ~S|cursor.execute("SELECT * FROM accounts WHERE id = %s", (account_id,))|
        ]
      }
    }
  end
  
  @doc """
  Command Injection via os.system pattern.
  
  Detects command execution using os.system with user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Python.command_injection_os_system()
      iex> vulnerable = ~S|os.system("ls " + user_input)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def command_injection_os_system do
    %Pattern{
      id: "python-command-injection-os-system",
      name: "Command Injection via os.system",
      description: "Unsanitized input in os.system() can lead to command injection",
      type: :command_injection,
      severity: :critical,
      languages: ["python"],
      regex: ~r/os\.system\s*\(\s*.*\+|os\.system\s*\(\s*f["'`].*\{/,
      default_tier: :protected,
      cwe_id: "CWE-78",
      owasp_category: "A03:2021",
      recommendation: "Use subprocess.run() with shell=False and validate inputs",
      test_cases: %{
        vulnerable: [
          ~S|os.system("ls " + user_input)|,
          ~S|os.system(f"ping {host}")|,
          ~S|os.system("cat /tmp/" + filename)|
        ],
        safe: [
          ~S|subprocess.run(["ls", user_input], shell=False)|,
          ~S|subprocess.run(["ping", host], shell=False)|,
          ~S|with open(os.path.join("/tmp", filename), 'r') as f: content = f.read()|
        ]
      }
    }
  end
  
  @doc """
  Command Injection via subprocess with shell=True pattern.
  
  Detects subprocess calls with shell=True.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Python.command_injection_subprocess_shell()
      iex> vulnerable = ~S|subprocess.run(cmd, shell=True)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def command_injection_subprocess_shell do
    %Pattern{
      id: "python-command-injection-subprocess-shell",
      name: "Command Injection via subprocess with shell=True",
      description: "Using subprocess with shell=True can lead to command injection",
      type: :command_injection,
      severity: :high,
      languages: ["python"],
      regex: ~r/subprocess\.(run|call|check_call|Popen)\s*\([^)]*shell\s*=\s*True/,
      default_tier: :protected,
      cwe_id: "CWE-78",
      owasp_category: "A03:2021",
      recommendation: "Use shell=False and pass command as list of arguments",
      test_cases: %{
        vulnerable: [
          ~S|subprocess.run(cmd, shell=True)|,
          ~S|subprocess.call("echo " + user_input, shell=True)|,
          ~S|subprocess.Popen(f"grep {pattern} file.txt", shell=True)|
        ],
        safe: [
          ~S|subprocess.run(["echo", user_input], shell=False)|,
          ~S|subprocess.call(["grep", pattern, "file.txt"])|,
          ~S|subprocess.Popen(["ls", "-la", directory])|
        ]
      }
    }
  end
  
  @doc """
  Insecure Deserialization via pickle pattern.
  
  Detects usage of pickle.loads/load which can execute arbitrary code.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Python.unsafe_pickle()
      iex> vulnerable = ~S|data = pickle.loads(user_data)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def unsafe_pickle do
    %Pattern{
      id: "python-unsafe-pickle",
      name: "Insecure Deserialization via pickle",
      description: "pickle.loads() can execute arbitrary code during deserialization",
      type: :deserialization,
      severity: :critical,
      languages: ["python"],
      regex: ~r/pickle\.(loads?|load)\s*\(/,
      default_tier: :public,
      cwe_id: "CWE-502",
      owasp_category: "A08:2021",
      recommendation: "Use json.loads() or implement custom deserialization with validation",
      test_cases: %{
        vulnerable: [
          ~S|data = pickle.loads(user_data)|,
          ~S|with open('data.pkl', 'rb') as f: obj = pickle.load(f)|,
          ~S|result = pickle.loads(base64.b64decode(encoded_data))|
        ],
        safe: [
          ~S|data = json.loads(user_data)|,
          ~S|with open('data.json', 'r') as f: obj = json.load(f)|,
          ~S|# Use a safe serialization format like JSON or MessagePack|
        ]
      }
    }
  end
  
  @doc """
  Code Injection via eval() pattern.
  
  Detects usage of eval() which can execute arbitrary code.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Python.unsafe_eval()
      iex> vulnerable = ~S|result = eval(user_input)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def unsafe_eval do
    %Pattern{
      id: "python-unsafe-eval",
      name: "Code Injection via eval()",
      description: "eval() can execute arbitrary Python code",
      type: :rce,
      severity: :critical,
      languages: ["python"],
      regex: ~r/\beval\s*\(/,
      default_tier: :public,
      cwe_id: "CWE-95",
      owasp_category: "A03:2021",
      recommendation: "Use ast.literal_eval() for safe evaluation of literals",
      test_cases: %{
        vulnerable: [
          ~S|result = eval(user_input)|,
          ~S|value = eval(request.args.get('expression'))|,
          ~S|computed = eval(f"2 + {user_number}")|
        ],
        safe: [
          ~S|result = ast.literal_eval(user_input)|,
          ~S|value = int(request.args.get('number', 0))|,
          ~S|computed = 2 + int(user_number)|
        ]
      }
    }
  end
  
  @doc """
  Path Traversal via open() pattern.
  
  Detects file operations with unsanitized paths.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Python.path_traversal_open()
      iex> vulnerable = ~S|open("/uploads/" + filename)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def path_traversal_open do
    %Pattern{
      id: "python-path-traversal-open",
      name: "Path Traversal via open()",
      description: "Unsanitized file paths in open() can lead to directory traversal",
      type: :path_traversal,
      severity: :medium,
      languages: ["python"],
      regex: ~r/(?:open\s*\(\s*[^)]*\+|open\s*\(\s*f["'`].*\{|=.*\+.*;\s*open\s*\()/,
      default_tier: :protected,
      cwe_id: "CWE-22",
      owasp_category: "A01:2021",
      recommendation: "Validate and sanitize file paths, use os.path.join() safely",
      test_cases: %{
        vulnerable: [
          ~S|open("/uploads/" + filename)|,
          ~S|with open(f"/tmp/{user_file}") as f:|,
          ~S|file_path = base_dir + "/" + user_input; open(file_path)|
        ],
        safe: [
          ~S|safe_name = os.path.basename(filename); open(os.path.join("/uploads", safe_name))|,
          ~S|if os.path.commonpath([base_dir, requested_path]) == base_dir: open(requested_path)|,
          ~S|from pathlib import Path; safe_path = Path(base_dir) / Path(filename).name|
        ]
      }
    }
  end
  
  @doc """
  Weak Cryptography using MD5 pattern.
  
  Detects usage of MD5 for cryptographic purposes.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Python.weak_hash_md5()
      iex> vulnerable = ~S|hashlib.md5(password.encode())|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def weak_hash_md5 do
    %Pattern{
      id: "python-weak-hash-md5",
      name: "Weak Cryptography - MD5",
      description: "MD5 is cryptographically broken and should not be used",
      type: :weak_crypto,
      severity: :medium,
      languages: ["python"],
      regex: ~r/hashlib\.md5\s*\(/,
      default_tier: :public,
      cwe_id: "CWE-327",
      owasp_category: "A02:2021",
      recommendation: "Use SHA-256 or SHA-3 for cryptographic hashing",
      test_cases: %{
        vulnerable: [
          ~S|hashlib.md5(password.encode())|,
          ~S|hash_value = hashlib.md5(data).hexdigest()|,
          ~S|import hashlib; h = hashlib.md5()|
        ],
        safe: [
          ~S|hashlib.sha256(password.encode())|,
          ~S|from passlib.hash import bcrypt; bcrypt.hash(password)|,
          ~S|import hashlib; h = hashlib.sha3_256()|
        ]
      }
    }
  end
  
  @doc """
  Weak Cryptography using SHA1 pattern.
  
  Detects usage of SHA1 for security purposes.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Python.weak_hash_sha1()
      iex> vulnerable = ~S|hashlib.sha1(data)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def weak_hash_sha1 do
    %Pattern{
      id: "python-weak-hash-sha1",
      name: "Weak Cryptography - SHA1",
      description: "SHA-1 is deprecated for security purposes",
      type: :weak_crypto,
      severity: :medium,
      languages: ["python"],
      regex: ~r/hashlib\.sha1\s*\(/,
      default_tier: :public,
      cwe_id: "CWE-327",
      owasp_category: "A02:2021",
      recommendation: "Use SHA-256 or SHA-3 for cryptographic hashing",
      test_cases: %{
        vulnerable: [
          ~S|hashlib.sha1(data)|,
          ~S|signature = hashlib.sha1(message.encode()).hexdigest()|,
          ~S|h = hashlib.sha1(); h.update(content)|
        ],
        safe: [
          ~S|hashlib.sha256(data)|,
          ~S|signature = hashlib.sha3_256(message.encode()).hexdigest()|,
          ~S|h = hashlib.sha512(); h.update(content)|
        ]
      }
    }
  end
  
  @doc """
  Debug Mode Enabled pattern.
  
  Detects DEBUG = True in Python code (common in Django).
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Python.debug_true()
      iex> vulnerable = ~S|DEBUG = True|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def debug_true do
    %Pattern{
      id: "python-debug-true",
      name: "Debug Mode Enabled",
      description: "Debug mode enabled in production exposes sensitive information",
      type: :information_disclosure,
      severity: :medium,
      languages: ["python"],
      regex: ~r/(?:DEBUG\s*=\s*True(?!\s*else)|\.config\s*\[\s*['"]DEBUG['"]\s*\]\s*=\s*True)/,
      default_tier: :public,
      cwe_id: "CWE-489",
      owasp_category: "A05:2021",
      recommendation: "Set DEBUG = False in production environments",
      test_cases: %{
        vulnerable: [
          ~S|DEBUG = True|,
          ~S|settings.DEBUG = True|,
          ~S|app.config['DEBUG'] = True|
        ],
        safe: [
          ~S|DEBUG = False|,
          ~S|DEBUG = os.environ.get('DEBUG', 'False') == 'True'|,
          ~S|if environment == 'development': DEBUG = True else: DEBUG = False|
        ]
      }
    }
  end
  
  @doc """
  Unsafe YAML Loading pattern.
  
  Detects yaml.load() without SafeLoader.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Python.unsafe_yaml_load()
      iex> vulnerable = ~S|data = yaml.load(user_input)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def unsafe_yaml_load do
    %Pattern{
      id: "python-unsafe-yaml-load",
      name: "Insecure Deserialization via yaml.load",
      description: "yaml.load() without SafeLoader can execute arbitrary code",
      type: :deserialization,
      severity: :critical,
      languages: ["python"],
      regex: ~r/yaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)/,
      default_tier: :protected,
      cwe_id: "CWE-502",
      owasp_category: "A08:2021",
      recommendation: "Use yaml.safe_load() or yaml.load() with SafeLoader",
      test_cases: %{
        vulnerable: [
          ~S|data = yaml.load(user_input)|,
          ~S|config = yaml.load(open('config.yml'))|,
          ~S|result = yaml.load(request.data)|
        ],
        safe: [
          ~S|data = yaml.safe_load(user_input)|,
          ~S|config = yaml.load(open('config.yml'), Loader=yaml.SafeLoader)|,
          ~S|result = yaml.safe_load(request.data)|
        ]
      }
    }
  end
end