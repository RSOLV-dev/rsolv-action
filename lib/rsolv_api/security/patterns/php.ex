defmodule RsolvApi.Security.Patterns.Php do
  @moduledoc """
  PHP security patterns for detecting vulnerabilities.
  
  This module contains 25 security patterns specifically designed for PHP
  code. Each pattern includes detection rules, test cases, and educational
  documentation.
  """
  
  
  # Import individual pattern modules
  alias RsolvApi.Security.Patterns.Php.SqlInjectionConcat
  alias RsolvApi.Security.Patterns.Php.SqlInjectionInterpolation
  alias RsolvApi.Security.Patterns.Php.CommandInjection
  alias RsolvApi.Security.Patterns.Php.XssEcho
  alias RsolvApi.Security.Patterns.Php.XssPrint
  alias RsolvApi.Security.Patterns.Php.FileInclusion
  alias RsolvApi.Security.Patterns.Php.FileUploadNoValidation
  alias RsolvApi.Security.Patterns.Php.WeakPasswordHash
  alias RsolvApi.Security.Patterns.Php.HardcodedCredentials
  alias RsolvApi.Security.Patterns.Php.InsecureRandom
  alias RsolvApi.Security.Patterns.Php.UnsafeDeserialization
  alias RsolvApi.Security.Patterns.Php.XxeVulnerability
  alias RsolvApi.Security.Patterns.Php.PathTraversal
  alias RsolvApi.Security.Patterns.Php.SsrfVulnerability
  alias RsolvApi.Security.Patterns.Php.SessionFixation
  alias RsolvApi.Security.Patterns.Php.WeakCrypto
  alias RsolvApi.Security.Patterns.Php.LdapInjection
  alias RsolvApi.Security.Patterns.Php.XpathInjection
  alias RsolvApi.Security.Patterns.Php.EvalUsage
  alias RsolvApi.Security.Patterns.Php.ExtractUsage
  alias RsolvApi.Security.Patterns.Php.RegisterGlobals
  alias RsolvApi.Security.Patterns.Php.OpenRedirect
  alias RsolvApi.Security.Patterns.Php.MissingCsrfToken
  alias RsolvApi.Security.Patterns.Php.DebugModeEnabled
  alias RsolvApi.Security.Patterns.Php.ErrorDisplay
  
  @doc """
  Returns all PHP security patterns.
  
  ## Examples
  
      iex> patterns = RsolvApi.Security.Patterns.Php.all()
      iex> length(patterns)
      25
      iex> Enum.all?(patterns, &match?(%RsolvApi.Security.Pattern{}, &1))
      true
  """
  def all do
    [
      sql_injection_concat(),
      sql_injection_interpolation(),
      command_injection(),
      xss_echo(),
      xss_print(),
      file_inclusion(),
      file_upload_no_validation(),
      weak_password_hash(),
      hardcoded_credentials(),
      insecure_random(),
      unsafe_deserialization(),
      xxe_vulnerability(),
      path_traversal(),
      ssrf_vulnerability(),
      session_fixation(),
      weak_crypto(),
      ldap_injection(),
      xpath_injection(),
      eval_usage(),
      extract_usage(),
      register_globals(),
      open_redirect(),
      missing_csrf_token(),
      debug_mode_enabled(),
      error_display()
    ]
  end
  
  @doc """
  SQL Injection via String Concatenation pattern.
  
  Detects direct concatenation of user input in SQL queries.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.sql_injection_concat()
      iex> pattern.id
      "php-sql-injection-concat"
      iex> pattern.severity
      :critical
  """
  defdelegate sql_injection_concat(), to: SqlInjectionConcat, as: :pattern
  
  @doc """
  SQL Injection via Variable Interpolation pattern.
  
  Detects user input interpolated directly into SQL strings.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.sql_injection_interpolation()
      iex> vulnerable = ~S|$query = "SELECT * FROM users WHERE name = '$_GET[name]'";|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  defdelegate sql_injection_interpolation(), to: SqlInjectionInterpolation, as: :pattern
  
  @doc """
  Command Injection pattern.
  
  Detects user input passed to system commands allowing remote code execution.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.command_injection()
      iex> pattern.id
      "php-command-injection"
      iex> pattern.severity
      :critical
  """
  defdelegate command_injection(), to: CommandInjection, as: :pattern
  
  @doc """
  XSS via echo pattern.
  
  Detects direct output of user input without escaping.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.xss_echo()
      iex> pattern.id
      "php-xss-echo"
      iex> pattern.severity
      :high
  """
  defdelegate xss_echo(), to: XssEcho, as: :pattern
  
  @doc """
  XSS via print pattern.
  
  Detects direct printing of user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.xss_print()
      iex> vulnerable = ~S|print $_POST['comment'];|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  defdelegate xss_print(), to: XssPrint, as: :pattern
  
  @doc """
  File Inclusion pattern.
  
  Detects dynamic file inclusion vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.file_inclusion()
      iex> vulnerable = ~S|include $_GET['page'] . '.php';|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  defdelegate file_inclusion(), to: FileInclusion, as: :pattern
  
  @doc """
  File Upload without Validation pattern.
  
  Detects file uploads without proper validation.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.file_upload_no_validation()
      iex> pattern.id
      "php-file-upload-no-validation"
      iex> pattern.severity
      :high
  """
  defdelegate file_upload_no_validation(), to: FileUploadNoValidation, as: :pattern
  
  @doc """
  Weak Password Hash pattern.
  
  Detects usage of weak hashing algorithms for passwords.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.weak_password_hash()
      iex> vulnerable = ~S|$hash = md5($password);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  defdelegate weak_password_hash(), to: WeakPasswordHash, as: :pattern
  
  @doc """
  Hardcoded Credentials pattern.
  
  Detects hardcoded passwords and API keys.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.hardcoded_credentials()
      iex> vulnerable = ~S|$password = "admin123";|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  defdelegate hardcoded_credentials(), to: HardcodedCredentials, as: :pattern
  
  @doc """
  Insecure Random pattern.
  
  Detects weak random number generation.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.insecure_random()
      iex> vulnerable = ~S|$token = rand(1000, 9999);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  defdelegate insecure_random(), to: InsecureRandom, as: :pattern
  
  @doc """
  Unsafe Deserialization pattern.
  
  Detects unsafe usage of unserialize().
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.unsafe_deserialization()
      iex> vulnerable = ~S|$data = unserialize($_COOKIE['data']);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  defdelegate unsafe_deserialization(), to: UnsafeDeserialization, as: :pattern
  
  @doc """
  XXE Vulnerability pattern.
  
  Detects XML External Entity vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.xxe_vulnerability()
      iex> vulnerable = ~S|$xml = simplexml_load_string($_POST['xml']);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  defdelegate xxe_vulnerability(), to: XxeVulnerability, as: :pattern
  
  @doc """
  Path Traversal pattern.
  
  Detects directory traversal vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.path_traversal()
      iex> vulnerable = ~S|include('./pages/' . $_GET['page']);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  defdelegate path_traversal(), to: PathTraversal, as: :pattern
  
  @doc """
  SSRF Vulnerability pattern.
  
  Detects Server-Side Request Forgery vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.ssrf_vulnerability()
      iex> vulnerable = ~S|$content = file_get_contents($_POST['url']);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  defdelegate ssrf_vulnerability(), to: SsrfVulnerability, as: :pattern
  
  @doc """
  Session Fixation pattern.
  
  Detects potential session fixation vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.session_fixation()
      iex> vulnerable = ~S|session_id($_GET['sid']);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  defdelegate session_fixation(), to: SessionFixation, as: :pattern
  
  @doc """
  Weak Cryptography pattern.
  
  Detects usage of weak cryptographic algorithms.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.weak_crypto()
      iex> vulnerable = ~S|$encrypted = mcrypt_encrypt(MCRYPT_DES, $key, $data, MCRYPT_MODE_ECB);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  defdelegate weak_crypto(), to: WeakCrypto, as: :pattern
  
  @doc """
  LDAP Injection pattern.
  
  Detects LDAP injection vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.ldap_injection()
      iex> vulnerable = ~S|ldap_search($ds, $dn, "(uid=$_GET[username])");|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  defdelegate ldap_injection(), to: LdapInjection, as: :pattern
  
  @doc """
  XPath Injection pattern.
  
  Detects XPath injection vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.xpath_injection()
      iex> vulnerable = ~S|$xpath->query("//user[name='$_GET[name]']");|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  defdelegate xpath_injection(), to: XpathInjection, as: :pattern
  
  @doc """
  Eval Usage pattern.
  
  Detects dangerous eval() usage.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.eval_usage()
      iex> vulnerable = ~S|eval($_POST['code']);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  defdelegate eval_usage(), to: EvalUsage, as: :pattern
  
  @doc """
  Extract Usage pattern.
  
  Detects dangerous extract() usage.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.extract_usage()
      iex> vulnerable = ~S|extract($_POST);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  defdelegate extract_usage(), to: ExtractUsage, as: :pattern
  
  @doc """
  Register Globals pattern.
  
  Detects code that might rely on register_globals.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.register_globals()
      iex> vulnerable = ~S|if ($authenticated) { show_content(); }|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  defdelegate register_globals(), to: RegisterGlobals, as: :pattern
  
  @doc """
  Open Redirect pattern.
  
  Detects open redirect vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.open_redirect()
      iex> vulnerable = ~S|header("Location: " . $_GET['url']);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  defdelegate open_redirect(), to: OpenRedirect, as: :pattern
  
  @doc """
  Missing CSRF Token pattern.
  
  Detects forms without CSRF protection.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.missing_csrf_token()
      iex> vulnerable = "if (\$_SERVER['REQUEST_METHOD'] === 'POST') { updateProfile(\$_POST['email']); }"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  defdelegate missing_csrf_token(), to: MissingCsrfToken, as: :pattern
  
  @doc """
  Debug Mode Enabled pattern.
  
  Detects debug mode or verbose errors enabled.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.debug_mode_enabled()
      iex> vulnerable = ~S|ini_set('display_errors', 1);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  defdelegate debug_mode_enabled(), to: DebugModeEnabled, as: :pattern
  
  @doc """
  Error Display pattern.
  
  Detects detailed error messages shown to users.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.error_display()
      iex> vulnerable = ~S|die("Database error: " . mysqli_error($conn));|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  defdelegate error_display(), to: ErrorDisplay, as: :pattern
end
