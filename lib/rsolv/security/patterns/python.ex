defmodule Rsolv.Security.Patterns.Python do
  @moduledoc """
  Python security patterns for detecting vulnerabilities.

  This module contains 12 security patterns specifically designed for Python
  code. Each pattern includes detection rules, test cases, and educational
  documentation.
  """

  # Import new pattern modules
  alias Rsolv.Security.Patterns.Python.{
    UnsafePickle,
    UnsafeEval,
    SqlInjectionFormat,
    SqlInjectionFstring,
    SqlInjectionConcat,
    CommandInjectionOsSystem,
    CommandInjectionSubprocessShell,
    PathTraversalOpen,
    WeakHashMd5,
    WeakHashSha1,
    DebugTrue,
    UnsafeYamlLoad
  }

  @doc """
  Returns all Python security patterns.

  ## Examples

      iex> patterns = Rsolv.Security.Patterns.Python.all()
      iex> length(patterns)
      12
      iex> Enum.all?(patterns, &match?(%Rsolv.Security.Pattern{}, &1))
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

      iex> pattern = Rsolv.Security.Patterns.Python.sql_injection_format()
      iex> pattern.id
      "python-sql-injection-format"
      iex> pattern.severity
      :high
      
  ## Detection Examples

      iex> pattern = Rsolv.Security.Patterns.Python.sql_injection_format()
      iex> vulnerable = ~S|cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      iex> safe = ~S|cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))|
      iex> Regex.match?(pattern.regex, safe)
      false
  """
  def sql_injection_format do
    SqlInjectionFormat.pattern()
  end

  @doc """
  SQL Injection via f-string formatting pattern.

  Detects SQL queries using f-strings with user input.

  ## Examples

      iex> pattern = Rsolv.Security.Patterns.Python.sql_injection_fstring()
      iex> pattern.id
      "python-sql-injection-fstring"
      iex> pattern.severity
      :high
      
  ## Detection Examples

      iex> pattern = Rsolv.Security.Patterns.Python.sql_injection_fstring()
      iex> vulnerable = ~S|cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      iex> safe = ~S|cursor.execute("SELECT * FROM users WHERE name = %s", (name,))|
      iex> Regex.match?(pattern.regex, safe)
      false
  """
  def sql_injection_fstring do
    SqlInjectionFstring.pattern()
  end

  @doc """
  SQL Injection via string concatenation pattern.

  Detects SQL queries built using string concatenation.

  ## Examples

      iex> pattern = Rsolv.Security.Patterns.Python.sql_injection_concat()
      iex> vulnerable = ~S|cursor.execute("SELECT * FROM users WHERE id = " + user_id)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def sql_injection_concat do
    SqlInjectionConcat.pattern()
  end

  @doc """
  Command Injection via os.system pattern.

  Detects command execution using os.system with user input.

  ## Examples

      iex> pattern = Rsolv.Security.Patterns.Python.command_injection_os_system()
      iex> vulnerable = ~S|os.system("ls " + user_input)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def command_injection_os_system do
    CommandInjectionOsSystem.pattern()
  end

  @doc """
  Command Injection via subprocess with shell=True pattern.

  Detects subprocess calls with shell=True.

  ## Examples

      iex> pattern = Rsolv.Security.Patterns.Python.command_injection_subprocess_shell()
      iex> vulnerable = ~S|subprocess.run(cmd, shell=True)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def command_injection_subprocess_shell do
    CommandInjectionSubprocessShell.pattern()
  end

  @doc """
  Insecure Deserialization via pickle pattern.

  Detects usage of pickle.loads/load which can execute arbitrary code.

  ## Examples

      iex> pattern = Rsolv.Security.Patterns.Python.unsafe_pickle()
      iex> vulnerable = ~S|data = pickle.loads(user_data)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def unsafe_pickle do
    UnsafePickle.pattern()
  end

  @doc """
  Code Injection via eval() pattern.

  Detects usage of eval() which can execute arbitrary code.

  ## Examples

      iex> pattern = Rsolv.Security.Patterns.Python.unsafe_eval()
      iex> vulnerable = ~S|result = eval(user_input)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def unsafe_eval do
    UnsafeEval.pattern()
  end

  @doc """
  Path Traversal via open() pattern.

  Detects file operations with unsanitized paths.

  ## Examples

      iex> pattern = Rsolv.Security.Patterns.Python.path_traversal_open()
      iex> vulnerable = ~S|open("/uploads/" + filename)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def path_traversal_open do
    PathTraversalOpen.pattern()
  end

  @doc """
  Weak Cryptography using MD5 pattern.

  Detects usage of MD5 for cryptographic purposes.

  ## Examples

      iex> pattern = Rsolv.Security.Patterns.Python.weak_hash_md5()
      iex> vulnerable = ~S|hashlib.md5(password.encode())|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def weak_hash_md5 do
    WeakHashMd5.pattern()
  end

  @doc """
  Weak Cryptography using SHA1 pattern.

  Detects usage of SHA1 for security purposes.

  ## Examples

      iex> pattern = Rsolv.Security.Patterns.Python.weak_hash_sha1()
      iex> vulnerable = ~S|hashlib.sha1(data)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def weak_hash_sha1 do
    WeakHashSha1.pattern()
  end

  @doc """
  Debug Mode Enabled pattern.

  Detects DEBUG = True in Python code (common in Django).

  ## Examples

      iex> pattern = Rsolv.Security.Patterns.Python.debug_true()
      iex> vulnerable = ~S|DEBUG = True|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def debug_true do
    DebugTrue.pattern()
  end

  @doc """
  Unsafe YAML Loading pattern.

  Detects yaml.load() without SafeLoader.

  ## Examples

      iex> pattern = Rsolv.Security.Patterns.Python.unsafe_yaml_load()
      iex> vulnerable = ~S|data = yaml.load(user_input)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def unsafe_yaml_load do
    UnsafeYamlLoad.pattern()
  end
end
