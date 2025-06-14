defmodule RsolvApi.Security.Patterns.Php do
  @moduledoc """
  PHP security patterns for detecting vulnerabilities.
  
  This module contains 25 security patterns specifically designed for PHP
  code. Each pattern includes detection rules, test cases, and educational
  documentation.
  """
  
  alias RsolvApi.Security.Pattern
  
  # Import individual pattern modules
  alias RsolvApi.Security.Patterns.Php.SqlInjectionConcat
  alias RsolvApi.Security.Patterns.Php.SqlInjectionInterpolation
  alias RsolvApi.Security.Patterns.Php.CommandInjection
  alias RsolvApi.Security.Patterns.Php.XssEcho
  
  @doc """
  Returns all PHP security patterns.
  
  ## Examples
  
      iex> patterns = RsolvApi.Security.Patterns.Php.all()
      iex> length(patterns)
      25
      iex> Enum.all?(patterns, &match?(%Pattern{}, &1))
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
  def xss_print do
    %Pattern{
      id: "php-xss-print",
      name: "XSS via print",
      description: "Direct printing of user input without escaping",
      type: :xss,
      severity: :high,
      languages: ["php"],
      regex: ~r/print\s+.*\$_(GET|POST|REQUEST|COOKIE)/,
      default_tier: :public,
      cwe_id: "CWE-79",
      owasp_category: "A03:2021",
      recommendation: "Use htmlspecialchars() before printing user input",
      test_cases: %{
        vulnerable: [
          ~S|print $_POST['comment'];|,
          ~S|print "Hello " . $_GET['user'];|
        ],
        safe: [
          ~S|print htmlspecialchars($_POST['comment'], ENT_QUOTES);|
        ]
      }
    }
  end
  
  @doc """
  File Inclusion pattern.
  
  Detects dynamic file inclusion vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.file_inclusion()
      iex> vulnerable = ~S|include $_GET['page'] . '.php';|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def file_inclusion do
    %Pattern{
      id: "php-file-inclusion",
      name: "File Inclusion Vulnerability",
      description: "Dynamic file inclusion with user input",
      type: :file_inclusion,
      severity: :critical,
      languages: ["php"],
      regex: ~r/(include|require|include_once|require_once)\s*\(?\s*.*\$_(GET|POST|REQUEST|COOKIE)/,
      default_tier: :protected,
      cwe_id: "CWE-98",
      owasp_category: "A03:2021",
      recommendation: "Use a whitelist of allowed files or avoid dynamic inclusion",
      test_cases: %{
        vulnerable: [
          ~S|include $_GET['page'] . '.php';|,
          ~S|require_once($_POST['module']);|
        ],
        safe: [
          ~S|$allowed = ['home', 'about', 'contact'];
$page = $_GET['page'];
if (in_array($page, $allowed)) {
    include $page . '.php';
}|
        ]
      }
    }
  end
  
  @doc """
  File Upload without Validation pattern.
  
  Detects file uploads without proper validation.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.file_upload_no_validation()
      iex> vulnerable = ~S|move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $_FILES['file']['name']);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def file_upload_no_validation do
    %Pattern{
      id: "php-file-upload-no-validation",
      name: "File Upload without Validation",
      description: "File uploads without type/content validation",
      type: :file_upload,
      severity: :high,
      languages: ["php"],
      regex: ~r/move_uploaded_file\s*\(\s*\$_FILES.*\['name'\]/,
      default_tier: :protected,
      cwe_id: "CWE-434",
      owasp_category: "A01:2021",
      recommendation: "Validate file type, size, and content. Use a safe upload directory",
      test_cases: %{
        vulnerable: [
          ~S|move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $_FILES['file']['name']);|
        ],
        safe: [
          ~S|$allowed = ['jpg', 'jpeg', 'png', 'gif'];
$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
if (in_array($ext, $allowed)) {
    $newname = uniqid() . '.' . $ext;
    move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $newname);
}|
        ]
      }
    }
  end
  
  @doc """
  Weak Password Hash pattern.
  
  Detects usage of weak hashing algorithms for passwords.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.weak_password_hash()
      iex> vulnerable = ~S|$hash = md5($password);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def weak_password_hash do
    %Pattern{
      id: "php-weak-password-hash",
      name: "Weak Password Hashing",
      description: "Using weak hashing algorithms for passwords",
      type: :weak_crypto,
      severity: :high,
      languages: ["php"],
      regex: ~r/(md5|sha1)\s*\(\s*.*password/,
      default_tier: :public,
      cwe_id: "CWE-916",
      owasp_category: "A02:2021",
      recommendation: "Use password_hash() with PASSWORD_DEFAULT or PASSWORD_ARGON2ID",
      test_cases: %{
        vulnerable: [
          ~S|$hash = md5($password);|,
          ~S|$stored = sha1($_POST['password'] . $salt);|
        ],
        safe: [
          ~S|$hash = password_hash($password, PASSWORD_DEFAULT);|,
          ~S|$hash = password_hash($password, PASSWORD_ARGON2ID);|
        ]
      }
    }
  end
  
  @doc """
  Hardcoded Credentials pattern.
  
  Detects hardcoded passwords and API keys.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.hardcoded_credentials()
      iex> vulnerable = ~S|$password = "admin123";|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def hardcoded_credentials do
    %Pattern{
      id: "php-hardcoded-credentials",
      name: "Hardcoded Credentials",
      description: "Passwords or API keys hardcoded in source",
      type: :hardcoded_secret,
      severity: :critical,
      languages: ["php"],
      regex: ~r/\$(password|api_key|secret|token)\s*=\s*["'][^"']{8,}/,
      default_tier: :public,
      cwe_id: "CWE-798",
      owasp_category: "A07:2021",
      recommendation: "Use environment variables or secure configuration files",
      test_cases: %{
        vulnerable: [
          ~S|$password = "admin123";|,
          ~S|$api_key = "sk_live_abcd1234efgh5678";|
        ],
        safe: [
          ~S|$password = getenv('DB_PASSWORD');|,
          ~S|$api_key = $_ENV['API_KEY'];|
        ]
      }
    }
  end
  
  @doc """
  Insecure Random pattern.
  
  Detects weak random number generation.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.insecure_random()
      iex> vulnerable = ~S|$token = rand(1000, 9999);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def insecure_random do
    %Pattern{
      id: "php-insecure-random",
      name: "Insecure Random Number Generation",
      description: "Using predictable random functions for security",
      type: :insecure_random,
      severity: :medium,
      languages: ["php"],
      regex: ~r/(rand|mt_rand|srand|mt_srand)\s*\(/,
      default_tier: :public,
      cwe_id: "CWE-338",
      owasp_category: "A02:2021",
      recommendation: "Use random_bytes() or random_int() for cryptographic randomness",
      test_cases: %{
        vulnerable: [
          ~S|$token = rand(1000, 9999);|,
          ~S|$session_id = mt_rand();|
        ],
        safe: [
          ~S|$token = bin2hex(random_bytes(16));|,
          ~S|$code = random_int(100000, 999999);|
        ]
      }
    }
  end
  
  @doc """
  Unsafe Deserialization pattern.
  
  Detects unsafe usage of unserialize().
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.unsafe_deserialization()
      iex> vulnerable = ~S|$data = unserialize($_COOKIE['data']);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def unsafe_deserialization do
    %Pattern{
      id: "php-unsafe-deserialization",
      name: "Unsafe Deserialization",
      description: "Using unserialize on user input can lead to RCE",
      type: :deserialization,
      severity: :critical,
      languages: ["php"],
      regex: ~r/unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/,
      default_tier: :protected,
      cwe_id: "CWE-502",
      owasp_category: "A08:2021",
      recommendation: "Use JSON instead of serialize/unserialize for user data",
      test_cases: %{
        vulnerable: [
          ~S|$data = unserialize($_COOKIE['data']);|,
          ~S|$obj = unserialize($_POST['object']);|
        ],
        safe: [
          ~S|$data = json_decode($_COOKIE['data'], true);|,
          ~S|// Or use allowed_classes option
$obj = unserialize($data, ['allowed_classes' => ['MyClass']]);|
        ]
      }
    }
  end
  
  @doc """
  XXE Vulnerability pattern.
  
  Detects XML External Entity vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.xxe_vulnerability()
      iex> vulnerable = ~S|$xml = simplexml_load_string($_POST['xml']);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def xxe_vulnerability do
    %Pattern{
      id: "php-xxe-vulnerability",
      name: "XML External Entity (XXE) Vulnerability",
      description: "Processing XML without disabling external entities",
      type: :xxe,
      severity: :high,
      languages: ["php"],
      regex: ~r/(simplexml_load_string|DOMDocument.*loadXML)\s*\(\s*\$_(GET|POST|REQUEST)/,
      default_tier: :protected,
      cwe_id: "CWE-611",
      owasp_category: "A05:2021",
      recommendation: "Disable external entity loading with libxml_disable_entity_loader(true)",
      test_cases: %{
        vulnerable: [
          ~S|$xml = simplexml_load_string($_POST['xml']);|,
          ~S|$doc->loadXML($_POST['data']);|
        ],
        safe: [
          ~S|libxml_disable_entity_loader(true);
$xml = simplexml_load_string($_POST['xml'], 'SimpleXMLElement', LIBXML_NOCDATA);|
        ]
      }
    }
  end
  
  @doc """
  Path Traversal pattern.
  
  Detects directory traversal vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.path_traversal()
      iex> vulnerable = ~S|include('./pages/' . $_GET['page']);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def path_traversal do
    %Pattern{
      id: "php-path-traversal",
      name: "Path Traversal",
      description: "File path manipulation vulnerability",
      type: :path_traversal,
      severity: :high,
      languages: ["php"],
      regex: ~r/(file_get_contents|fopen|include|require)\s*\([^)]*\$_(GET|POST|REQUEST)/,
      default_tier: :protected,
      cwe_id: "CWE-22",
      owasp_category: "A01:2021",
      recommendation: "Validate and sanitize file paths, use basename() or realpath()",
      test_cases: %{
        vulnerable: [
          ~S|include('./pages/' . $_GET['page']);|,
          ~S|$content = file_get_contents('uploads/' . $_GET['file']);|
        ],
        safe: [
          ~S|$page = basename($_GET['page']);
$allowed = ['home.php', 'about.php'];
if (in_array($page, $allowed)) {
    include('./pages/' . $page);
}|
        ]
      }
    }
  end
  
  @doc """
  SSRF Vulnerability pattern.
  
  Detects Server-Side Request Forgery vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.ssrf_vulnerability()
      iex> vulnerable = ~S|$content = file_get_contents($_POST['url']);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def ssrf_vulnerability do
    %Pattern{
      id: "php-ssrf-vulnerability",
      name: "Server-Side Request Forgery (SSRF)",
      description: "Unvalidated URLs in server-side requests",
      type: :ssrf,
      severity: :high,
      languages: ["php"],
      regex: ~r/(file_get_contents|curl_exec|fopen)\s*\(\s*\$_(GET|POST|REQUEST)/,
      default_tier: :protected,
      cwe_id: "CWE-918",
      owasp_category: "A10:2021",
      recommendation: "Validate URLs against an allowlist before making requests",
      test_cases: %{
        vulnerable: [
          ~S|$content = file_get_contents($_POST['url']);|,
          ~S|curl_setopt($ch, CURLOPT_URL, $_GET['api']);|
        ],
        safe: [
          ~S|$allowed_hosts = ['api.example.com', 'cdn.example.com'];
$url = $_POST['url'];
$host = parse_url($url, PHP_URL_HOST);
if (in_array($host, $allowed_hosts)) {
    $content = file_get_contents($url);
}|
        ]
      }
    }
  end
  
  @doc """
  Session Fixation pattern.
  
  Detects potential session fixation vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.session_fixation()
      iex> vulnerable = ~S|session_id($_GET['sid']);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def session_fixation do
    %Pattern{
      id: "php-session-fixation",
      name: "Session Fixation",
      description: "Accepting session ID from user input",
      type: :session_management,
      severity: :high,
      languages: ["php"],
      regex: ~r/session_id\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/,
      default_tier: :protected,
      cwe_id: "CWE-384",
      owasp_category: "A07:2021",
      recommendation: "Regenerate session ID after login with session_regenerate_id(true)",
      test_cases: %{
        vulnerable: [
          ~S|session_id($_GET['sid']);|,
          ~S|session_id($_COOKIE['PHPSESSID']);|
        ],
        safe: [
          ~S|// After successful login
session_regenerate_id(true);|
        ]
      }
    }
  end
  
  @doc """
  Weak Cryptography pattern.
  
  Detects usage of weak cryptographic algorithms.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.weak_crypto()
      iex> vulnerable = ~S|$encrypted = mcrypt_encrypt(MCRYPT_DES, $key, $data, MCRYPT_MODE_ECB);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def weak_crypto do
    %Pattern{
      id: "php-weak-crypto",
      name: "Weak Cryptography",
      description: "Using deprecated or weak encryption",
      type: :weak_crypto,
      severity: :medium,
      languages: ["php"],
      regex: ~r/(mcrypt_|MCRYPT_DES|MCRYPT_3DES|ECB)/,
      default_tier: :public,
      cwe_id: "CWE-327",
      owasp_category: "A02:2021",
      recommendation: "Use openssl functions with AES-256-GCM",
      test_cases: %{
        vulnerable: [
          ~S|$encrypted = mcrypt_encrypt(MCRYPT_DES, $key, $data, MCRYPT_MODE_ECB);|
        ],
        safe: [
          ~S|$encrypted = openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv, $tag);|
        ]
      }
    }
  end
  
  @doc """
  LDAP Injection pattern.
  
  Detects LDAP injection vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.ldap_injection()
      iex> vulnerable = ~S|ldap_search($ds, $dn, "(uid=$_GET[username])");|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def ldap_injection do
    %Pattern{
      id: "php-ldap-injection",
      name: "LDAP Injection",
      description: "User input in LDAP queries without escaping",
      type: :ldap_injection,
      severity: :high,
      languages: ["php"],
      regex: ~r/ldap_search\s*\([^,]+,[^,]+,\s*["'][^"']*\$_(GET|POST|REQUEST)/,
      default_tier: :protected,
      cwe_id: "CWE-90",
      owasp_category: "A03:2021",
      recommendation: "Use ldap_escape() to sanitize user input",
      test_cases: %{
        vulnerable: [
          ~S|ldap_search($ds, $dn, "(uid=$_GET[username])");|
        ],
        safe: [
          ~S|$username = ldap_escape($_GET['username'], '', LDAP_ESCAPE_FILTER);
ldap_search($ds, $dn, "(uid=$username)");|
        ]
      }
    }
  end
  
  @doc """
  XPath Injection pattern.
  
  Detects XPath injection vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.xpath_injection()
      iex> vulnerable = ~S|$xpath->query("//user[name='$_GET[name]']");|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def xpath_injection do
    %Pattern{
      id: "php-xpath-injection",
      name: "XPath Injection",
      description: "User input in XPath queries",
      type: :xpath_injection,
      severity: :high,
      languages: ["php"],
      regex: ~r/->query\s*\([^)]*\$_(GET|POST|REQUEST)/,
      default_tier: :protected,
      cwe_id: "CWE-643",
      owasp_category: "A03:2021",
      recommendation: "Validate and escape user input in XPath queries",
      test_cases: %{
        vulnerable: [
          ~S|$xpath->query("//user[name='$_GET[name]']");|
        ],
        safe: [
          ~S|$name = preg_replace('/[^a-zA-Z0-9]/', '', $_GET['name']);
$xpath->query("//user[name='$name']");|
        ]
      }
    }
  end
  
  @doc """
  Eval Usage pattern.
  
  Detects dangerous eval() usage.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.eval_usage()
      iex> vulnerable = ~S|eval($_POST['code']);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def eval_usage do
    %Pattern{
      id: "php-eval-usage",
      name: "Code Injection via eval()",
      description: "Using eval() with user input",
      type: :rce,
      severity: :critical,
      languages: ["php"],
      regex: ~r/eval\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE)/,
      default_tier: :protected,
      cwe_id: "CWE-95",
      owasp_category: "A03:2021",
      recommendation: "Never use eval() with user input. Find alternative solutions",
      test_cases: %{
        vulnerable: [
          ~S|eval($_POST['code']);|,
          ~S|eval("return " . $_GET['expression'] . ";");|
        ],
        safe: [
          ~S|// Parse specific operations instead
switch($_POST['operation']) {
    case 'add': $result = $a + $b; break;
    case 'subtract': $result = $a - $b; break;
}|
        ]
      }
    }
  end
  
  @doc """
  Extract Usage pattern.
  
  Detects dangerous extract() usage.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.extract_usage()
      iex> vulnerable = ~S|extract($_POST);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def extract_usage do
    %Pattern{
      id: "php-extract-usage",
      name: "Variable Overwrite via extract()",
      description: "Using extract() on user input can overwrite variables",
      type: :input_validation,
      severity: :high,
      languages: ["php"],
      regex: ~r/extract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/,
      default_tier: :protected,
      cwe_id: "CWE-621",
      owasp_category: "A03:2021",
      recommendation: "Avoid extract() on user input or use EXTR_SKIP flag",
      test_cases: %{
        vulnerable: [
          ~S|extract($_POST);|,
          ~S|extract($_GET);|
        ],
        safe: [
          ~S|// Better: access directly
$name = $_POST['name'] ?? '';|,
          ~S|// Or use EXTR_SKIP to not overwrite
extract($_POST, EXTR_SKIP);|
        ]
      }
    }
  end
  
  @doc """
  Register Globals pattern.
  
  Detects code that might rely on register_globals.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.register_globals()
      iex> vulnerable = ~S|if ($authenticated) { // $authenticated might come from $_GET|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def register_globals do
    %Pattern{
      id: "php-register-globals",
      name: "Register Globals Dependency",
      description: "Code that might rely on register_globals",
      type: :input_validation,
      severity: :medium,
      languages: ["php"],
      regex: ~r/if\s*\(\s*\$(?!_)(authenticated|admin|user_id|logged_in)\s*\)/,
      default_tier: :public,
      cwe_id: "CWE-473",
      owasp_category: "A04:2021",
      recommendation: "Initialize all variables and don't rely on register_globals",
      test_cases: %{
        vulnerable: [
          ~S|if ($authenticated) { // $authenticated might come from $_GET|,
          ~S|if ($is_admin) { show_admin_panel(); }|
        ],
        safe: [
          ~S|$authenticated = isset($_SESSION['authenticated']) ? $_SESSION['authenticated'] : false;
if ($authenticated) {|
        ]
      }
    }
  end
  
  @doc """
  Open Redirect pattern.
  
  Detects open redirect vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.open_redirect()
      iex> vulnerable = ~S|header("Location: " . $_GET['url']);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def open_redirect do
    %Pattern{
      id: "php-open-redirect",
      name: "Open Redirect",
      description: "Unvalidated redirect URLs",
      type: :open_redirect,
      severity: :medium,
      languages: ["php"],
      regex: ~r/header\s*\(\s*["']Location:\s*["']?\s*\.\s*\$_(GET|POST|REQUEST)/,
      default_tier: :public,
      cwe_id: "CWE-601",
      owasp_category: "A01:2021",
      recommendation: "Validate redirect URLs against an allowlist",
      test_cases: %{
        vulnerable: [
          ~S|header("Location: " . $_GET['url']);|,
          ~S|header('Location: ' . $_POST['redirect']);|
        ],
        safe: [
          ~S|$allowed_urls = ['/home', '/dashboard', '/profile'];
$redirect = $_GET['url'];
if (in_array($redirect, $allowed_urls)) {
    header("Location: " . $redirect);
}|
        ]
      }
    }
  end
  
  @doc """
  Missing CSRF Token pattern.
  
  Detects forms without CSRF protection.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.missing_csrf_token()
      iex> vulnerable = "if (\$_SERVER['REQUEST_METHOD'] === 'POST') { updateProfile(\$_POST['email']); }"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def missing_csrf_token do
    %Pattern{
      id: "php-missing-csrf-token",
      name: "Missing CSRF Protection",
      description: "POST request handling without CSRF token validation",
      type: :csrf,
      severity: :medium,
      languages: ["php"],
      regex: ~r/if\s*\(\s*\$_SERVER\['REQUEST_METHOD'\]\s*===?\s*['"]POST['"]\s*\)\s*\{(?!.*csrf)/s,
      default_tier: :public,
      cwe_id: "CWE-352",
      owasp_category: "A01:2021",
      recommendation: "Implement CSRF token validation for state-changing operations",
      test_cases: %{
        vulnerable: [
          ~S|if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    updateProfile($_POST['email']);
}|
        ],
        safe: [
          ~S"""
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die('CSRF token validation failed');
    }
    updateProfile($_POST['email']);
}
"""
        ]
      }
    }
  end
  
  @doc """
  Debug Mode Enabled pattern.
  
  Detects debug mode or verbose errors enabled.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.debug_mode_enabled()
      iex> vulnerable = ~S|ini_set('display_errors', 1);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def debug_mode_enabled do
    %Pattern{
      id: "php-debug-mode-enabled",
      name: "Debug Mode Enabled",
      description: "Debug settings that expose sensitive information",
      type: :information_disclosure,
      severity: :medium,
      languages: ["php"],
      regex: ~r/ini_set\s*\(\s*['"]display_errors['"]\s*,\s*(1|true|on)/,
      default_tier: :public,
      cwe_id: "CWE-489",
      owasp_category: "A05:2021",
      recommendation: "Disable debug mode and error display in production",
      test_cases: %{
        vulnerable: [
          ~S|ini_set('display_errors', 1);|,
          ~S|error_reporting(E_ALL);|
        ],
        safe: [
          ~S|ini_set('display_errors', 0);
ini_set('log_errors', 1);|
        ]
      }
    }
  end
  
  @doc """
  Error Display pattern.
  
  Detects detailed error messages shown to users.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Php.error_display()
      iex> vulnerable = ~S|die("Database error: " . mysqli_error($conn));|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def error_display do
    %Pattern{
      id: "php-error-display",
      name: "Detailed Error Display",
      description: "Showing detailed error messages to users",
      type: :information_disclosure,
      severity: :low,
      languages: ["php"],
      regex: ~r/(die|exit)\s*\(\s*["'][^"']*error[^"']*["']\s*\.\s*\w+_(error|errno)/,
      default_tier: :public,
      cwe_id: "CWE-209",
      owasp_category: "A05:2021",
      recommendation: "Log errors internally and show generic messages to users",
      test_cases: %{
        vulnerable: [
          ~S|die("Database error: " . mysqli_error($conn));|,
          ~S|exit("Query failed: " . pg_last_error());|
        ],
        safe: [
          ~S|error_log("Database error: " . mysqli_error($conn));
die("An error occurred. Please try again later.");|
        ]
      }
    }
  end
end