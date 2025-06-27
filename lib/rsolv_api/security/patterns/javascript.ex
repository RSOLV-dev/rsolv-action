defmodule RsolvApi.Security.Patterns.Javascript do
  @moduledoc """
  JavaScript security patterns for detecting vulnerabilities.
  
  This module contains 30 security patterns specifically designed for JavaScript
  and TypeScript code. Each pattern includes detection rules, test cases, and
  educational documentation.
  """
  
  
  # Import new pattern modules
  alias RsolvApi.Security.Patterns.Javascript.{
    SqlInjectionConcat,
    SqlInjectionInterpolation,
    XssInnerhtml,
    XssDocumentWrite,
    XssJqueryHtml,
    XssReactDangerously,
    XssDomManipulation,
    CommandInjectionExec,
    CommandInjectionSpawn,
    PathTraversalJoin,
    PathTraversalConcat,
    WeakCryptoMd5,
    WeakCryptoSha1,
    HardcodedSecretPassword,
    HardcodedSecretApiKey,
    EvalUserInput,
    UnsafeRegex,
    PrototypePollution,
    InsecureDeserialization,
    OpenRedirect,
    XxeExternalEntities,
    NosqlInjection,
    LdapInjection,
    XpathInjection,
    Ssrf,
    MissingCsrfProtection,
    JwtNoneAlgorithm,
    DebugConsoleLog,
    InsecureRandom,
    TimingAttackComparison
  }
  
  @doc """
  Returns all JavaScript security patterns.
  
  ## Examples
  
      iex> patterns = RsolvApi.Security.Patterns.Javascript.all()
      iex> length(patterns)
      30
      iex> Enum.all?(patterns, &match?(%RsolvApi.Security.Pattern{}, &1))
      true
  """
  def all do
    [
      sql_injection_concat(),
      sql_injection_interpolation(),
      xss_innerhtml(),
      xss_document_write(),
      xss_jquery_html(),
      xss_react_dangerously(),
      xss_dom_manipulation(),
      command_injection_exec(),
      command_injection_spawn(),
      path_traversal_join(),
      path_traversal_concat(),
      weak_crypto_md5(),
      weak_crypto_sha1(),
      hardcoded_secret_password(),
      hardcoded_secret_api_key(),
      eval_user_input(),
      unsafe_regex(),
      open_redirect(),
      xxe_external_entities(),
      prototype_pollution(),
      insecure_random(),
      timing_attack_comparison(),
      nosql_injection(),
      ldap_injection(),
      xpath_injection(),
      server_side_request_forgery(),
      insecure_deserialization(),
      missing_csrf_protection(),
      jwt_none_algorithm(),
      debug_console_log()
    ]
  end
  
  @doc """
  SQL Injection via String Concatenation pattern.
  
  Detects SQL queries built using string concatenation with user input,
  which is vulnerable to SQL injection attacks.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.sql_injection_concat()
      iex> pattern.id
      "js-sql-injection-concat"
      iex> pattern.severity
      :critical
  """
  def sql_injection_concat do
    SqlInjectionConcat.pattern()
  end
  
  @doc """
  SQL Injection via String Interpolation pattern.
  
  Detects SQL queries using template literals with unescaped user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.sql_injection_interpolation()
      iex> pattern.id
      "js-sql-injection-interpolation"
      iex> pattern.severity
      :critical
  """
  def sql_injection_interpolation do
    SqlInjectionInterpolation.pattern()
  end
  
  @doc """
  Cross-Site Scripting (XSS) via innerHTML pattern.
  
  Detects direct assignment of user input to innerHTML, which can execute scripts.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.xss_innerhtml()
      iex> pattern.id
      "js-xss-innerhtml"
      iex> pattern.severity
      :high
  """
  def xss_innerhtml do
    XssInnerhtml.pattern()
  end
  
  @doc """
  Cross-Site Scripting (XSS) via document.write pattern.
  
  Detects usage of document.write with user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.xss_document_write()
      iex> pattern.id
      "js-xss-document-write"
      iex> pattern.severity
      :high
  """
  def xss_document_write do
    XssDocumentWrite.pattern()
  end
  
  @doc """
  Cross-Site Scripting (XSS) via jQuery html() pattern.
  
  Detects jQuery html() method with user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.xss_jquery_html()
      iex> pattern.id
      "js-xss-jquery-html"
      iex> pattern.severity
      :high
  """
  def xss_jquery_html do
    XssJqueryHtml.pattern()
  end
  
  @doc """
  Cross-Site Scripting (XSS) via React dangerouslySetInnerHTML pattern.
  
  Detects React's dangerouslySetInnerHTML prop with user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.xss_react_dangerously()
      iex> pattern.id
      "js-xss-react-dangerously"
      iex> pattern.severity
      :high
  """
  def xss_react_dangerously do
    XssReactDangerously.pattern()
  end
  
  @doc """
  Cross-Site Scripting (XSS) via DOM Manipulation pattern.
  
  Detects DOM manipulation methods like insertAdjacentHTML and jQuery append with user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.xss_dom_manipulation()
      iex> pattern.id
      "js-xss-dom-manipulation"
      iex> pattern.severity
      :high
  """
  def xss_dom_manipulation do
    XssDomManipulation.pattern()
  end
  
  @doc """
  Command Injection via child_process.exec pattern.
  
  Detects command execution with user input using exec.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.command_injection_exec()
      iex> pattern.id
      "js-command-injection-exec"
      iex> pattern.severity
      :critical
  """
  def command_injection_exec do
    CommandInjectionExec.pattern()
  end
  
  @doc """
  Command Injection via child_process.spawn pattern.
  
  Detects unsafe spawn usage with shell option and user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.command_injection_spawn()
      iex> vulnerable = ~S|spawn("sh", ["-c", userInput], {shell: true})|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def command_injection_spawn do
    CommandInjectionSpawn.pattern()
  end
  
  @doc """
  Path Traversal via path.join pattern.
  
  Detects path traversal vulnerabilities using path.join with user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.path_traversal_join()
      iex> vulnerable = ~S|path.join("/uploads", req.params.filename)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def path_traversal_join do
    PathTraversalJoin.pattern()
  end
  
  @doc """
  Path Traversal via string concatenation pattern.
  
  Detects file path construction using string concatenation.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.path_traversal_concat()
      iex> vulnerable = ~S|fs.readFile("./uploads/" + filename)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def path_traversal_concat do
    PathTraversalConcat.pattern()
  end
  
  @doc """
  Weak Cryptography using MD5 pattern.
  
  Detects usage of MD5 for cryptographic purposes.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.weak_crypto_md5()
      iex> vulnerable = ~S|crypto.createHash('md5')|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def weak_crypto_md5 do
    WeakCryptoMd5.pattern()
  end
  
  @doc """
  Weak Cryptography using SHA1 pattern.
  
  Detects usage of SHA1 for security purposes.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.weak_crypto_sha1()
      iex> vulnerable = ~S|crypto.createHash('sha1')|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def weak_crypto_sha1 do
    WeakCryptoSha1.pattern()
  end
  
  @doc """
  Hardcoded Password pattern.
  
  Detects hardcoded passwords in source code.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.hardcoded_secret_password()
      iex> vulnerable = ~s(const password = "admin123")
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def hardcoded_secret_password do
    HardcodedSecretPassword.pattern()
  end
  
  @doc """
  Hardcoded API Key pattern.
  
  Detects hardcoded API keys and tokens.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.hardcoded_secret_api_key()
      iex> vulnerable = ~s(const apiKey = "sk-1234567890abcdef")
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def hardcoded_secret_api_key do
    HardcodedSecretApiKey.pattern()
  end
  
  @doc """
  Dangerous eval() usage pattern.
  
  Detects eval() being used with user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.eval_user_input()
      iex> vulnerable = ~S|eval(userInput)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def eval_user_input do
    EvalUserInput.pattern()
  end
  
  @doc """
  Unsafe Regular Expression pattern.
  
  Detects regex patterns vulnerable to ReDoS attacks.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.unsafe_regex()
      iex> vulnerable = ~S|new RegExp("(a+)+$")|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def unsafe_regex do
    UnsafeRegex.pattern()
  end
  
  @doc """
  Open Redirect pattern.
  
  Detects redirects using user-controlled URLs.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.open_redirect()
      iex> vulnerable = ~S|res.redirect(req.query.url)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def open_redirect do
    OpenRedirect.pattern()
  end
  
  @doc """
  XML External Entity (XXE) pattern.
  
  Detects XML parsers with external entity processing enabled.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.xxe_external_entities()
      iex> vulnerable = ~S|parser = new DOMParser()|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def xxe_external_entities do
    XxeExternalEntities.pattern()
  end
  
  @doc """
  Prototype Pollution pattern.
  
  Detects object property assignment that could pollute prototypes.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.prototype_pollution()
      iex> vulnerable = ~S|obj[key] = value|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def prototype_pollution do
    PrototypePollution.pattern()
  end
  
  @doc """
  Insecure Random Number Generation pattern.
  
  Detects Math.random() used for security purposes.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.insecure_random()
      iex> vulnerable = ~S|const token = Math.random().toString()|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def insecure_random do
    InsecureRandom.pattern()
  end
  
  @doc """
  Timing Attack via String Comparison pattern.
  
  Detects non-constant time string comparisons for secrets.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.timing_attack_comparison()
      iex> vulnerable = ~S|if (userToken === secretToken)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def timing_attack_comparison do
    TimingAttackComparison.pattern()
  end
  
  @doc """
  NoSQL Injection pattern.
  
  Detects NoSQL query injection vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.nosql_injection()
      iex> vulnerable = ~S|db.users.find({username: req.body.username})|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def nosql_injection do
    NosqlInjection.pattern()
  end
  
  @doc """
  LDAP Injection pattern.
  
  Detects LDAP query injection vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.ldap_injection()
      iex> vulnerable = ~S|ldap.search("cn=" + username)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def ldap_injection do
    LdapInjection.pattern()
  end
  
  @doc """
  XPath Injection pattern.
  
  Detects XPath query injection vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.xpath_injection()
      iex> vulnerable = ~S|xpath.select("//user[name='" + username + "']")|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def xpath_injection do
    XpathInjection.pattern()
  end
  
  @doc """
  Server-Side Request Forgery (SSRF) pattern.
  
  Detects SSRF vulnerabilities in HTTP requests.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.server_side_request_forgery()
      iex> vulnerable = ~S|axios.get(req.body.url)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def server_side_request_forgery do
    Ssrf.pattern()
  end
  
  @doc """
  Insecure Deserialization pattern.
  
  Detects unsafe deserialization of user input that can lead to RCE.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.insecure_deserialization()
      iex> pattern.id
      "js-insecure-deserialization"
      iex> pattern.severity
      :high
  """
  def insecure_deserialization do
    InsecureDeserialization.pattern()
  end
  
  @doc """
  Missing CSRF Protection pattern.
  
  Detects state-changing routes without CSRF protection.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.missing_csrf_protection()
      iex> vulnerable = ~S|app.post('/api/transfer', (req, res) => {})|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def missing_csrf_protection do
    MissingCsrfProtection.pattern()
  end
  
  @doc """
  JWT None Algorithm pattern.
  
  Detects JWT verification that might accept 'none' algorithm.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.jwt_none_algorithm()
      iex> vulnerable = ~S|jwt.verify(token, secret)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def jwt_none_algorithm do
    JwtNoneAlgorithm.pattern()
  end
  
  @doc """
  Debug Console Log pattern.
  
  Detects console.log statements that might leak sensitive data.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.debug_console_log()
      iex> vulnerable = ~S|console.log(password)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def debug_console_log do
    DebugConsoleLog.pattern()
  end
end