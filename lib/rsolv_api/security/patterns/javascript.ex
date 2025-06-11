defmodule RsolvApi.Security.Patterns.Javascript do
  @moduledoc """
  JavaScript security patterns for detecting vulnerabilities.
  
  This module contains 27 security patterns specifically designed for JavaScript
  and TypeScript code. Each pattern includes detection rules, test cases, and
  educational documentation.
  """
  
  alias RsolvApi.Security.Pattern
  
  @doc """
  Returns all JavaScript security patterns.
  
  ## Examples
  
      iex> patterns = RsolvApi.Security.Patterns.Javascript.all()
      iex> length(patterns)
      27
      iex> Enum.all?(patterns, &match?(%Pattern{}, &1))
      true
  """
  def all do
    [
      sql_injection_concat(),
      sql_injection_interpolation(),
      xss_innerhtml(),
      xss_document_write(),
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
      
  ## Detection Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.sql_injection_concat()
      iex> vulnerable = ~s(const query = "SELECT * FROM users WHERE id = " + userId)
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      iex> safe = ~s(const query = "SELECT * FROM users WHERE id = ?")
      iex> Regex.match?(pattern.regex, safe)
      false
  """
  def sql_injection_concat do
    %Pattern{
      id: "js-sql-injection-concat",
      name: "SQL Injection via String Concatenation",
      description: "Direct concatenation of user input in SQL queries can lead to SQL injection attacks",
      type: :sql_injection,
      severity: :critical,
      languages: ["javascript", "typescript"],
      regex: ~r/(?:const|let|var)\s+\w+\s*=\s*["'`](?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|FROM|WHERE).*["'`]\s*\+\s*\w+/i,
      default_tier: :protected,
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation: "Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.",
      test_cases: %{
        vulnerable: [
          ~s(const query = "SELECT * FROM users WHERE id = " + userId),
          ~S|let sql = "DELETE FROM posts WHERE author = '" + username + "'"|,
          ~S|var statement = `UPDATE accounts SET balance = ${amount} WHERE id = ` + accountId|
        ],
        safe: [
          ~s(const query = "SELECT * FROM users WHERE id = ?"),
          ~S|db.query("SELECT * FROM users WHERE id = ?", [userId])|,
          ~S|const prepared = db.prepare("INSERT INTO logs (message) VALUES (?)")|
        ]
      }
    }
  end
  
  @doc """
  SQL Injection via String Interpolation pattern.
  
  Detects SQL queries using template literals with unescaped user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.sql_injection_interpolation()
      iex> vulnerable = ~S|const query = `SELECT * FROM users WHERE name = '${userName}'`|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def sql_injection_interpolation do
    %Pattern{
      id: "js-sql-injection-interpolation",
      name: "SQL Injection via String Interpolation",
      description: "Template literals with unescaped variables in SQL queries",
      type: :sql_injection,
      severity: :critical,
      languages: ["javascript", "typescript"],
      regex: ~r/`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|FROM|WHERE)[^`]*\$\{[^}]+\}[^`]*`/i,
      default_tier: :protected,
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation: "Use parameterized queries instead of string interpolation for SQL queries.",
      test_cases: %{
        vulnerable: [
          ~S|const query = `SELECT * FROM users WHERE name = '${userName}'`|,
          ~S|db.query(`DELETE FROM posts WHERE id = ${postId}`)|,
          ~S|const sql = `UPDATE users SET email = '${email}' WHERE id = ${id}`|
        ],
        safe: [
          ~S|db.query("SELECT * FROM users WHERE name = ?", [userName])|,
          ~S|const query = db.prepare("DELETE FROM posts WHERE id = ?")|,
          ~S|await db.execute("UPDATE users SET email = ? WHERE id = ?", [email, id])|
        ]
      }
    }
  end
  
  @doc """
  Cross-Site Scripting (XSS) via innerHTML pattern.
  
  Detects direct assignment of user input to innerHTML, which can execute scripts.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.xss_innerhtml()
      iex> vulnerable = ~s(element.innerHTML = userInput)
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def xss_innerhtml do
    %Pattern{
      id: "js-xss-innerhtml",
      name: "XSS via innerHTML",
      description: "Direct assignment to innerHTML with user input can execute malicious scripts",
      type: :xss,
      severity: :high,
      languages: ["javascript", "typescript"],
      regex: ~r/\.innerHTML\s*=\s*(?!.*DOMPurify).*(?:req\.|request\.|params\.|query\.|body\.|user|input|data)/i,
      default_tier: :public,
      cwe_id: "CWE-79",
      owasp_category: "A03:2021",
      recommendation: "Use textContent for text, or sanitize HTML input before using innerHTML.",
      test_cases: %{
        vulnerable: [
          ~s(element.innerHTML = userInput),
          ~s(div.innerHTML = req.body.comment),
          ~S|document.getElementById('output').innerHTML = params.message|
        ],
        safe: [
          ~s(element.textContent = userInput),
          ~S|element.innerHTML = DOMPurify.sanitize(userInput)|,
          ~s(div.innerText = req.body.comment)
        ]
      }
    }
  end
  
  @doc """
  Cross-Site Scripting (XSS) via document.write pattern.
  
  Detects usage of document.write with user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.xss_document_write()
      iex> vulnerable = ~S|document.write(userInput)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def xss_document_write do
    %Pattern{
      id: "js-xss-document-write",
      name: "XSS via document.write",
      description: "document.write with user input can execute scripts",
      type: :xss,
      severity: :high,
      languages: ["javascript", "typescript"],
      regex: ~r/document\.write\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.|user|input|data)/i,
      default_tier: :public,
      cwe_id: "CWE-79",
      owasp_category: "A03:2021",
      recommendation: "Avoid document.write. Use DOM methods like appendChild with createTextNode.",
      test_cases: %{
        vulnerable: [
          ~S|document.write(userInput)|,
          ~S|document.write("<div>" + req.query.name + "</div>")|,
          ~S|document.write(`Hello ${params.username}`)|
        ],
        safe: [
          ~S|const text = document.createTextNode(userInput); element.appendChild(text)|,
          ~s(element.textContent = userInput),
          ~S|element.appendChild(document.createTextNode(params.username))|
        ]
      }
    }
  end
  
  @doc """
  Command Injection via child_process.exec pattern.
  
  Detects command execution with user input using exec.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.command_injection_exec()
      iex> vulnerable = ~S|exec("ls " + userInput)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def command_injection_exec do
    %Pattern{
      id: "js-command-injection-exec",
      name: "Command Injection via exec",
      description: "Using exec with user input can lead to command injection",
      type: :command_injection,
      severity: :critical,
      languages: ["javascript", "typescript"],
      regex: ~r/(?:exec|execSync)\s*\([^)]*(?:\+|\$\{)[^)]*[a-zA-Z]/,
      default_tier: :protected,
      cwe_id: "CWE-78",
      owasp_category: "A03:2021",
      recommendation: "Use execFile with argument array instead of exec. Validate and sanitize all user input.",
      test_cases: %{
        vulnerable: [
          ~S|exec("ls " + userInput)|,
          ~S|execSync(`git clone ${repoUrl}`)|,
          ~S|exec("cat /tmp/" + req.params.file)|
        ],
        safe: [
          ~S|execFile("ls", [userInput])|,
          ~S|spawn("git", ["clone", repoUrl])|,
          ~S|execFile("cat", ["/tmp/safe.txt"])|
        ]
      }
    }
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
    %Pattern{
      id: "js-command-injection-spawn",
      name: "Command Injection via spawn with shell",
      description: "Using spawn with shell:true and user input enables command injection",
      type: :command_injection,
      severity: :critical,
      languages: ["javascript", "typescript"],
      regex: ~r/spawn\s*\([^)]*\{[^}]*shell\s*:\s*true/i,
      default_tier: :protected,
      cwe_id: "CWE-78",
      owasp_category: "A03:2021",
      recommendation: "Avoid shell:true. Use spawn without shell option and pass arguments as array.",
      test_cases: %{
        vulnerable: [
          ~S|spawn("sh", ["-c", userInput], {shell: true})|,
          ~S|spawn(cmd, {shell: true, cwd: req.body.path})|,
          ~S|spawn("bash", ["-c", `echo ${userData}`], {shell: true})|
        ],
        safe: [
          ~S|spawn("echo", [userData])|,
          ~S|spawn("ls", ["-la", directory])|,
          ~S|execFile("git", ["status"], {cwd: safePath})|
        ]
      }
    }
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
    %Pattern{
      id: "js-path-traversal-join",
      name: "Path Traversal via path.join",
      description: "Using path.join with user input can lead to directory traversal",
      type: :path_traversal,
      severity: :high,
      languages: ["javascript", "typescript"],
      regex: ~r/path\.join\s*\([^)]*,\s*(?:req\.|request\.|params\.|query\.|body\.|user[A-Z]|userInput|input(?!.*sanitize)|data)/i,
      default_tier: :protected,
      cwe_id: "CWE-22",
      owasp_category: "A01:2021",
      recommendation: "Validate and sanitize file paths. Use path.resolve and check if result is within expected directory.",
      test_cases: %{
        vulnerable: [
          ~S|path.join("/uploads", req.params.filename)|,
          ~S|const file = path.join(baseDir, userInput)|,
          ~S|fs.readFile(path.join("./data", req.query.file))|
        ],
        safe: [
          ~S|const safePath = path.join("/uploads", path.basename(filename))|,
          ~S|if (resolvedPath.startsWith(baseDir)) { /* safe */ }|,
          ~S|const file = path.join(baseDir, sanitize(userInput))|
        ]
      }
    }
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
    %Pattern{
      id: "js-path-traversal-concat",
      name: "Path Traversal via String Concatenation",
      description: "Building file paths with string concatenation is vulnerable to traversal attacks",
      type: :path_traversal,
      severity: :high,
      languages: ["javascript", "typescript"],
      regex: ~r/(?:readFile|writeFile|unlink|mkdir|rmdir|access|stat)(?:Sync)?\s*\([^)]*(?:["'`][^"'`]*["'`]\s*\+|`[^`]*\$\{)/i,
      default_tier: :protected,
      cwe_id: "CWE-22",
      owasp_category: "A01:2021",
      recommendation: "Use path.join with path.basename or validate paths are within expected directory.",
      test_cases: %{
        vulnerable: [
          ~S|fs.readFile("./uploads/" + filename)|,
          ~S|fs.writeFile("/tmp/" + req.body.name, data)|,
          ~S|const content = fs.readFileSync(`./data/${userFile}`)|
        ],
        safe: [
          ~S|fs.readFile(path.join("./uploads", path.basename(filename)))|,
          ~S|const safeName = sanitizeFilename(req.body.name); fs.writeFile(path.join("/tmp", safeName), data)|,
          ~S|if (isPathSafe(userFile)) { fs.readFile(path.join("./data", userFile)) }|
        ]
      }
    }
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
    %Pattern{
      id: "js-weak-crypto-md5",
      name: "Weak Cryptography - MD5",
      description: "MD5 is cryptographically broken and should not be used",
      type: :weak_crypto,
      severity: :medium,
      languages: ["javascript", "typescript"],
      regex: ~r/crypto\.createHash\s*\(\s*['"`]md5['"`]\s*\)/i,
      default_tier: :public,
      cwe_id: "CWE-328",
      owasp_category: "A02:2021",
      recommendation: "Use SHA-256 or SHA-3 for hashing. For passwords, use bcrypt, scrypt, or argon2.",
      test_cases: %{
        vulnerable: [
          ~S|crypto.createHash('md5')|,
          ~S|const hash = crypto.createHash("md5").update(password).digest("hex")|,
          ~S|require('crypto').createHash('MD5')|
        ],
        safe: [
          ~S|crypto.createHash('sha256')|,
          ~S|await bcrypt.hash(password, 10)|,
          ~S|crypto.createHash('sha3-256')|
        ]
      }
    }
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
    %Pattern{
      id: "js-weak-crypto-sha1",
      name: "Weak Cryptography - SHA1",
      description: "SHA1 is vulnerable to collision attacks",
      type: :weak_crypto,
      severity: :medium,
      languages: ["javascript", "typescript"],
      regex: ~r/crypto\.createHash\s*\(\s*['"`]sha1['"`]\s*\)/i,
      default_tier: :public,
      cwe_id: "CWE-328",
      owasp_category: "A02:2021",
      recommendation: "Use SHA-256 or SHA-3 instead of SHA1.",
      test_cases: %{
        vulnerable: [
          ~S|crypto.createHash('sha1')|,
          ~S|const hash = crypto.createHash("sha1").update(data).digest()|,
          ~S|crypto.createHash('SHA1')|
        ],
        safe: [
          ~S|crypto.createHash('sha256')|,
          ~S|crypto.createHash('sha3-256')|,
          ~S|crypto.createHash('sha512')|
        ]
      }
    }
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
    %Pattern{
      id: "js-hardcoded-password",
      name: "Hardcoded Password",
      description: "Passwords should never be hardcoded in source code",
      type: :hardcoded_secret,
      severity: :high,
      languages: ["javascript", "typescript"],
      regex: ~r/(?:password|passwd|pwd)\s*[=:]\s*["'`][^"'`]{4,}["'`]/i,
      default_tier: :public,
      cwe_id: "CWE-798",
      owasp_category: "A07:2021",
      recommendation: "Store passwords in environment variables or secure configuration management systems.",
      test_cases: %{
        vulnerable: [
          ~s(const password = "admin123"),
          ~S|let dbPassword = 'secretpass'|,
          ~s(var config = { password: "mysecret123" })
        ],
        safe: [
          ~s(const password = process.env.DB_PASSWORD),
          ~S|const password = config.get('database.password')|,
          ~S|const password = await secretManager.getSecret('db-password')|
        ]
      }
    }
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
    %Pattern{
      id: "js-hardcoded-api-key",
      name: "Hardcoded API Key",
      description: "API keys should not be hardcoded in source code",
      type: :hardcoded_secret,
      severity: :high,
      languages: ["javascript", "typescript"],
      regex: ~r/(?:api[_-]?key|api[_-]?secret|token)\s*[=:]\s*["'`][\w\-]{16,}["'`]/i,
      default_tier: :public,
      cwe_id: "CWE-798",
      owasp_category: "A07:2021",
      recommendation: "Store API keys in environment variables or secure key management systems.",
      test_cases: %{
        vulnerable: [
          ~s(const apiKey = "sk-1234567890abcdef"),
          ~s(const API_KEY = "abcd1234efgh5678ijkl"),
          ~s(let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
        ],
        safe: [
          ~s(const apiKey = process.env.API_KEY),
          ~S|const token = getTokenFromVault()|,
          ~S|const apiSecret = await keyManager.getKey('api-secret')|
        ]
      }
    }
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
    %Pattern{
      id: "js-eval-user-input",
      name: "Dangerous eval() with User Input",
      description: "Using eval() with user input can execute arbitrary code",
      type: :rce,
      severity: :critical,
      languages: ["javascript", "typescript"],
      regex: ~r/eval\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.|user|input|data)/i,
      default_tier: :protected,
      cwe_id: "CWE-94",
      owasp_category: "A03:2021",
      recommendation: "Avoid eval(). Use JSON.parse() for JSON data or find safer alternatives.",
      test_cases: %{
        vulnerable: [
          ~S|eval(userInput)|,
          ~S|eval(req.body.code)|,
          ~S|const result = eval("2 + " + params.number)|
        ],
        safe: [
          ~S|JSON.parse(userInput)|,
          ~S|const fn = new Function("return " + sanitizedExpression)|,
          ~S|const result = calculateSafely(params.number)|
        ]
      }
    }
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
    %Pattern{
      id: "js-unsafe-regex",
      name: "Regular Expression Denial of Service (ReDoS)",
      description: "Regex with nested quantifiers can cause exponential backtracking",
      type: :denial_of_service,
      severity: :medium,
      languages: ["javascript", "typescript"],
      regex: ~r/(?:RegExp|\/)[^\/]*\([^)]*\+[^)]*\)[^)]*\+/,
      default_tier: :public,
      cwe_id: "CWE-1333",
      owasp_category: "A05:2021",
      recommendation: "Avoid nested quantifiers in regex. Use atomic groups or possessive quantifiers.",
      test_cases: %{
        vulnerable: [
          ~S|new RegExp("(a+)+$")|,
          ~S|/(x+x+)+y/.test(input)|,
          ~S|const pattern = /(a*)*b/|
        ],
        safe: [
          ~S|new RegExp("a+$")|,
          ~S|/x+y/.test(input)|,
          ~s(const pattern = /a*b/)
        ]
      }
    }
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
    %Pattern{
      id: "js-open-redirect",
      name: "Open Redirect Vulnerability",
      description: "Redirecting to user-controlled URLs can lead to phishing attacks",
      type: :open_redirect,
      severity: :medium,
      languages: ["javascript", "typescript"],
      regex: ~r/(?:res\.redirect|window\.location\.href\s*=|location\.replace)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.|user|input|data)/i,
      default_tier: :public,
      cwe_id: "CWE-601",
      owasp_category: "A01:2021",
      recommendation: "Validate redirect URLs against a whitelist of allowed destinations.",
      test_cases: %{
        vulnerable: [
          ~S|res.redirect(req.query.url)|,
          ~s(window.location.href = params.redirectTo),
          ~S|location.replace(userInput)|
        ],
        safe: [
          ~S|if (isValidRedirect(url)) { res.redirect(url) }|,
          ~S|res.redirect("/dashboard")|,
          ~S|const safeUrl = validateUrl(req.query.url); res.redirect(safeUrl)|
        ]
      }
    }
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
    %Pattern{
      id: "js-xxe-external-entities",
      name: "XML External Entity (XXE) Injection",
      description: "XML parsers with external entities enabled can read files and perform SSRF",
      type: :xxe,
      severity: :high,
      languages: ["javascript", "typescript"],
      regex: ~r/new\s+(?:DOMParser|XMLParser)|parseXML\s*\(|\.parseFromString\s*\(/i,
      default_tier: :protected,
      cwe_id: "CWE-611",
      owasp_category: "A05:2021",
      recommendation: "Disable external entity processing in XML parsers.",
      test_cases: %{
        vulnerable: [
          ~S|parser = new DOMParser()|,
          ~S|const doc = parser.parseFromString(xmlData, "text/xml")|,
          ~S|$.parseXML(userXml)|
        ],
        safe: [
          ~S|const parser = new DOMParser(); parser.parseFromString(sanitizedXml, "text/xml")|,
          ~S|const safeParser = createSafeXmlParser()|,
          ~S|JSON.parse(jsonData) // Use JSON instead of XML|
        ]
      }
    }
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
    %Pattern{
      id: "js-prototype-pollution",
      name: "Prototype Pollution",
      description: "Unsafe object property assignment can pollute object prototypes",
      type: :deserialization,
      severity: :high,
      languages: ["javascript", "typescript"],
      regex: ~r/\[[^\]]+\]\s*=(?!=)|Object\.assign\s*\([^,)]+,\s*(?:req\.|request\.|params\.|query\.|body\.|user|input|data)/i,
      default_tier: :protected,
      cwe_id: "CWE-1321",
      owasp_category: "A08:2021",
      recommendation: "Validate object keys, avoid direct property assignment with user input.",
      test_cases: %{
        vulnerable: [
          ~S|obj[key] = value|,
          ~S|Object.assign(config, req.body)|,
          ~S|target[userKey] = userValue|
        ],
        safe: [
          ~S|if (!key.includes('__proto__')) { obj[key] = value }|,
          ~S|const safe = Object.create(null); safe[key] = value|,
          ~S|Object.assign(config, sanitize(req.body))|
        ]
      }
    }
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
    %Pattern{
      id: "js-insecure-random",
      name: "Insecure Random Number Generation",
      description: "Math.random() is not cryptographically secure",
      type: :insecure_random,
      severity: :medium,
      languages: ["javascript", "typescript"],
      regex: ~r/(?:token|key|password|secret|salt|nonce)[^;]*=.*Math\.random\s*\(\s*\)|Math\.random\s*\(\s*\)[^;]*(?:token|key|password|secret|salt|nonce)/i,
      default_tier: :public,
      cwe_id: "CWE-330",
      owasp_category: "A02:2021",
      recommendation: "Use crypto.randomBytes() or crypto.getRandomValues() for security purposes.",
      test_cases: %{
        vulnerable: [
          ~S|const token = Math.random().toString()|,
          ~S|const sessionId = Math.random() * 1000000|,
          ~S|const salt = Math.random().toString(36)|
        ],
        safe: [
          ~S|const token = crypto.randomBytes(32).toString('hex')|,
          ~S|const sessionId = crypto.randomUUID()|,
          ~S|const salt = crypto.getRandomValues(new Uint8Array(16))|
        ]
      }
    }
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
    %Pattern{
      id: "js-timing-attack",
      name: "Timing Attack via String Comparison",
      description: "Direct string comparison of secrets can leak information via timing",
      type: :timing_attack,
      severity: :low,
      languages: ["javascript", "typescript"],
      regex: ~r/(?:===|==|!==|!=)\s*(?:secret|token|password|key|hash)/i,
      default_tier: :protected,
      cwe_id: "CWE-208",
      owasp_category: "A04:2021",
      recommendation: "Use crypto.timingSafeEqual() for comparing secrets.",
      test_cases: %{
        vulnerable: [
          ~S|if (userToken === secretToken)|,
          ~s(return password == storedPassword),
          ~S|if (req.headers.authorization !== apiKey)|
        ],
        safe: [
          ~S|crypto.timingSafeEqual(Buffer.from(userToken), Buffer.from(secretToken))|,
          ~S|bcrypt.compare(password, storedPassword)|,
          ~S|const valid = timingSafeCompare(req.headers.authorization, apiKey)|
        ]
      }
    }
  end
  
  @doc """
  NoSQL Injection pattern.
  
  Detects NoSQL query injection vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.nosql_injection()
      iex> vulnerable = ~S|db.find({username: req.body.username})|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def nosql_injection do
    %Pattern{
      id: "js-nosql-injection",
      name: "NoSQL Injection",
      description: "Direct use of user input in NoSQL queries can lead to injection",
      type: :nosql_injection,
      severity: :high,
      languages: ["javascript", "typescript"],
      regex: ~r/\.(find|update|delete|remove|insert)\s*\(\s*\{[^}]*(?:req\.|request\.|params\.|query\.|body\.|user|input|data)/i,
      default_tier: :protected,
      cwe_id: "CWE-943",
      owasp_category: "A03:2021",
      recommendation: "Validate input types and use parameterized queries for NoSQL databases.",
      test_cases: %{
        vulnerable: [
          ~S|db.find({username: req.body.username})|,
          ~S|collection.update({_id: params.id}, {$set: req.body})|,
          ~S|users.delete({email: query.email})|
        ],
        safe: [
          ~S|db.find({username: String(req.body.username)})|,
          ~S|collection.update({_id: ObjectId(params.id)}, {$set: sanitize(req.body)})|,
          ~S|users.delete({email: validator.isEmail(query.email) ? query.email : null})|
        ]
      }
    }
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
    %Pattern{
      id: "js-ldap-injection",
      name: "LDAP Injection",
      description: "Unescaped user input in LDAP queries can modify query logic",
      type: :ldap_injection,
      severity: :high,
      languages: ["javascript", "typescript"],
      regex: ~r/ldap\.(?:search|bind|add|modify|delete)\s*\([^)]*(?:\+|`)[^)]*(?:req\.|request\.|params\.|query\.|body\.|user|input|data)/i,
      default_tier: :protected,
      cwe_id: "CWE-90",
      owasp_category: "A03:2021",
      recommendation: "Escape special LDAP characters in user input.",
      test_cases: %{
        vulnerable: [
          ~S|ldap.search("cn=" + username)|,
          ~S|ldap.search(`(&(uid=${uid})(role=admin))`)|,
          ~S|client.bind("uid=" + user + ",ou=users,dc=example,dc=com", password)|
        ],
        safe: [
          ~S|ldap.search("cn=" + ldap.escape(username))|,
          ~S|const filter = ldap.parseFilter("(&(uid=?)(role=admin))"); filter.setValue(0, uid)|,
          ~S|client.bind(ldap.escapeDN(`uid=${user},ou=users,dc=example,dc=com`), password)|
        ]
      }
    }
  end
  
  @doc """
  XPath Injection pattern.
  
  Detects XPath query injection vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.xpath_injection()
      iex> vulnerable = ~S|xpath.select("//user[name='" + username + "']"))|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def xpath_injection do
    %Pattern{
      id: "js-xpath-injection",
      name: "XPath Injection",
      description: "Unescaped user input in XPath queries can modify query logic",
      type: :xpath_injection,
      severity: :high,
      languages: ["javascript", "typescript"],
      regex: ~r/xpath\.(?:select|evaluate)\s*\([^)]*(?:\+|`)[^)]*(?:req\.|request\.|params\.|query\.|body\.|user|input|data)/i,
      default_tier: :protected,
      cwe_id: "CWE-643",
      owasp_category: "A03:2021",
      recommendation: "Use parameterized XPath queries or properly escape user input.",
      test_cases: %{
        vulnerable: [
          ~S|xpath.select("//user[name='" + username + "']"))|,
          ~S|doc.evaluate(`/users/user[@id='${userId}']`, doc)|,
          ~S|xpath.select("//product[price<" + maxPrice + "]")|
        ],
        safe: [
          ~S|xpath.select("//user[name=$username]", {username: escapeXPath(username)})|,
          ~S|const query = xpath.compile("//user[@id=$id]"); query.select({id: userId})|,
          ~S|xpath.select("//product[price<$price]", {price: parseFloat(maxPrice)})|
        ]
      }
    }
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
    %Pattern{
      id: "js-ssrf",
      name: "Server-Side Request Forgery (SSRF)",
      description: "Making HTTP requests to user-controlled URLs can access internal resources",
      type: :ssrf,
      severity: :high,
      languages: ["javascript", "typescript"],
      regex: ~r/(?:axios|fetch|request|http|https)\.(?:get|post|put|delete|request)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.|user|input|data)/i,
      default_tier: :protected,
      cwe_id: "CWE-918",
      owasp_category: "A10:2021",
      recommendation: "Validate URLs against allowlist, block private IP ranges and sensitive protocols.",
      test_cases: %{
        vulnerable: [
          ~S|axios.get(req.body.url)|,
          ~S|fetch(userProvidedUrl)|,
          ~S|request(params.webhook_url, (err, res) => {})|
        ],
        safe: [
          ~S|if (isAllowedUrl(req.body.url)) { axios.get(req.body.url) }|,
          ~S|const url = new URL(userUrl); if (allowedHosts.includes(url.hostname)) { fetch(url) }|,
          ~S|axios.get(ALLOWED_APIS[req.body.api_name])|
        ]
      }
    }
  end
  
  @doc """
  Insecure Deserialization pattern.
  
  Detects unsafe deserialization of user input.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.insecure_deserialization()
      iex> vulnerable = ~S|JSON.parse(req.body.data)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def insecure_deserialization do
    %Pattern{
      id: "js-insecure-deserialization",
      name: "Insecure Deserialization",
      description: "Deserializing untrusted data can lead to remote code execution",
      type: :deserialization,
      severity: :high,
      languages: ["javascript", "typescript"],
      regex: ~r/(?:JSON\.parse|deserialize|unserialize|pickle\.loads|yaml\.load)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.|user|input|data)/i,
      default_tier: :protected,
      cwe_id: "CWE-502",
      owasp_category: "A08:2021",
      recommendation: "Validate data structure before deserialization. Use safe parsing methods.",
      test_cases: %{
        vulnerable: [
          ~S|JSON.parse(req.body.data)|,
          ~S|const obj = deserialize(userInput)|,
          ~S|yaml.load(req.body.config)|
        ],
        safe: [
          ~S|try { const data = JSON.parse(req.body.data); validateSchema(data) } catch(e) {}|,
          ~S|const obj = JSON.parse(sanitizeJson(userInput))|,
          ~S|yaml.safeLoad(req.body.config)|
        ]
      }
    }
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
    %Pattern{
      id: "js-missing-csrf",
      name: "Missing CSRF Protection",
      description: "State-changing endpoints need CSRF protection",
      type: :csrf,
      severity: :medium,
      languages: ["javascript", "typescript"],
      regex: ~r/app\.(?:post|put|patch|delete)\s*\(\s*['"`][^'"`]+['"`]\s*,\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{(?!.*csrf)/i,
      default_tier: :public,
      cwe_id: "CWE-352",
      owasp_category: "A01:2021",
      recommendation: "Implement CSRF tokens for all state-changing operations.",
      test_cases: %{
        vulnerable: [
          ~S|app.post('/api/transfer', (req, res) => {})|,
          ~S|router.put('/user/update', async (req, res) => {})|,
          ~S|app.delete('/account', handler)|
        ],
        safe: [
          ~S|app.post('/api/transfer', csrfProtection, (req, res) => {})|,
          ~S|app.use(csrf()); app.post('/transfer', (req, res) => {})|,
          ~S|app.post('/api/transfer', (req, res) => { verifyCsrf(req.body.csrf_token) })|
        ]
      }
    }
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
    %Pattern{
      id: "js-jwt-none-algorithm",
      name: "JWT None Algorithm Vulnerability",
      description: "JWT verification without algorithm validation can be bypassed",
      type: :authentication,
      severity: :high,
      languages: ["javascript", "typescript"],
      regex: ~r/jwt\.verify\s*\([^,)]+,[^,)]+(?:,\s*\{(?![^}]*algorithms)[^}]*\}|(?:,\s*[^{])?)?\s*\)/i,
      default_tier: :protected,
      cwe_id: "CWE-347",
      owasp_category: "A02:2021",
      recommendation: "Always specify allowed algorithms in JWT verification.",
      test_cases: %{
        vulnerable: [
          ~S|jwt.verify(token, secret)|,
          ~S|jwt.verify(token, publicKey, {issuer: 'myapp'})|,
          ~S|const decoded = jwt.verify(req.headers.authorization, key)|
        ],
        safe: [
          ~S|jwt.verify(token, secret, {algorithms: ['HS256']})|,
          ~S|jwt.verify(token, publicKey, {algorithms: ['RS256'], issuer: 'myapp'})|,
          ~S|jwt.verify(token, key, {algorithms: ['HS256', 'HS384', 'HS512']})|
        ]
      }
    }
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
    %Pattern{
      id: "js-debug-console-log",
      name: "Sensitive Data in Console Logs",
      description: "Console logs can expose sensitive information in production",
      type: :information_disclosure,
      severity: :low,
      languages: ["javascript", "typescript"],
      regex: ~r/console\.(?:log|info|warn|error)\s*\([^)]*(?:password|secret|token|key|credential|auth)/i,
      default_tier: :public,
      cwe_id: "CWE-532",
      owasp_category: "A09:2021",
      recommendation: "Remove console.log statements or use proper logging that filters sensitive data.",
      test_cases: %{
        vulnerable: [
          ~S|console.log(password)|,
          ~S|console.error("Auth failed for token:", token)|,
          ~S|console.info({apiKey: config.apiKey})|
        ],
        safe: [
          ~S|logger.debug("User authenticated", {userId: user.id})|,
          ~S|console.log("Login attempt for user:", username)|,
          ~S|if (isDevelopment) { console.log(debugInfo) }|
        ]
      }
    }
  end
end