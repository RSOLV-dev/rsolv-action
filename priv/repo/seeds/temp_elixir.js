
const VulnerabilityType = {
  SQL_INJECTION: 'sql_injection',
  XSS: 'xss',
  COMMAND_INJECTION: 'command_injection',
  PATH_TRAVERSAL: 'path_traversal',
  HARDCODED_SECRET: 'hardcoded_secret',
  WEAK_CRYPTO: 'weak_crypto',
  BROKEN_ACCESS_CONTROL: 'broken_access_control',
  SENSITIVE_DATA_EXPOSURE: 'sensitive_data_exposure',
  XML_EXTERNAL_ENTITIES: 'xxe',
  SECURITY_MISCONFIGURATION: 'security_misconfiguration',
  VULNERABLE_COMPONENTS: 'vulnerable_components',
  BROKEN_AUTHENTICATION: 'broken_authentication',
  INSECURE_DESERIALIZATION: 'insecure_deserialization',
  INSUFFICIENT_LOGGING: 'insufficient_logging',
  UNVALIDATED_REDIRECT: 'open_redirect',
  SSRF: 'ssrf',
  LDAP_INJECTION: 'ldap_injection',
  NOSQL_INJECTION: 'nosql_injection',
  CSRF: 'csrf',
  XXE: 'xxe',
  DESERIALIZATION: 'deserialization',
  RCE: 'rce',
  // Ruby/Rails specific
  MASS_ASSIGNMENT: 'mass_assignment',
  UNSAFE_REFLECTION: 'unsafe_reflection',
  DEBUG_MODE: 'debug_mode',
  WEAK_CRYPTOGRAPHY: 'weak_cryptography',
  // Django specific
  TEMPLATE_INJECTION: 'template_injection',
  ORM_INJECTION: 'orm_injection',
  MIDDLEWARE_BYPASS: 'middleware_bypass'
};
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.elixirSecurityPatterns = void 0;
const types_js_1 = {};
exports.elixirSecurityPatterns = [
    {
        id: 'elixir-sql-injection-interpolation',
        type: types_js_1.VulnerabilityType.SQL_INJECTION,
        name: 'Ecto SQL Injection via String Interpolation',
        description: 'Detects SQL injection through string interpolation in Ecto queries',
        patterns: {
            regex: [
                /Repo\.query!?\s*\(\s*["'].*?#\{[^}]+\}.*?["']/gi,
                /Ecto\.Adapters\.SQL\.query!?\s*\([^,]+,\s*["'].*?#\{[^}]+\}.*?["']/gi,
                /fragment\s*\(\s*["'][^"']*#\{[^}]+\}[^"']*["']/gi,
                /from\s*\([^)]+\)\s*,\s*where:\s*fragment\s*\(\s*["'][^"']*#\{[^}]+\}/gi,
                /from\s*\(\s*\w+\s+in\s+\w+\s*,\s*where:\s*fragment\s*\(/gi,
                /from\s*\(\s*\w+\s+in\s+["'][^"']+["']\s*,\s*where:\s*fragment\s*\(\s*["'][^"']*#\{[^}]+\}/gi,
                /fragment\s*\(\s*["'][^#]*'\s*#\{[^}]+\}\s*'[^"]*["']/gi
            ]
        },
        severity: 'critical',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['elixir'],
        remediation: 'Use parameterized queries with Ecto. Use ^variable syntax or pass parameters separately: Repo.query!("SELECT * FROM users WHERE id = $1", [id])',
        examples: {
            vulnerable: 'Repo.query!("SELECT * FROM users WHERE name = \'#{name}\'")',
            secure: 'Repo.query!("SELECT * FROM users WHERE name = $1", [name])'
        }
    },
    {
        id: 'elixir-sql-injection-fragment',
        type: types_js_1.VulnerabilityType.SQL_INJECTION,
        name: 'Unsafe Ecto Fragment Usage',
        description: 'Detects potentially unsafe use of Ecto fragments with user input',
        patterns: {
            regex: [
                /fragment\s*\(\s*["'][^"']*\?\s*=\s*ANY\s*\(\s*\?\s*\)["']\s*,\s*\^/gi,
                /fragment\s*\([^)]*\$\d+[^)]*\)/gi,
                /where:\s*fragment\s*\(\s*["'][^"']*["']\s*\)/gi
            ]
        },
        severity: 'high',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['elixir'],
        remediation: 'Be careful with Ecto fragment usage. Ensure all user inputs are properly sanitized and use parameterized placeholders. Consider using Ecto query DSL instead of fragments when possible',
        examples: {
            vulnerable: 'from(u in User, where: fragment("? = ANY(?)", ^field, ^values))',
            secure: 'from(u in User, where: field(u, ^field) in ^values)'
        }
    },
    {
        id: 'elixir-command-injection-system',
        type: types_js_1.VulnerabilityType.COMMAND_INJECTION,
        name: 'OS Command Injection in Elixir',
        description: 'Detects command injection vulnerabilities in system calls',
        patterns: {
            regex: [
                /System\.cmd\s*\([^,]+,\s*\[[^\]]*#\{[^}]+\}[^\]]*\]/gi,
                /System\.shell\s*\(\s*["'][^"']*#\{[^}]+\}[^"']*["']/gi,
                /:os\.cmd\s*\(\s*['"][^'"]*#\{[^}]+\}[^'"]*['"]/gi,
                /Port\.open\s*\(\s*\{\s*:spawn\s*,\s*["'][^"']*#\{[^}]+\}[^"']*["']/gi
            ]
        },
        severity: 'critical',
        cweId: 'CWE-78',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['elixir'],
        remediation: 'Use Elixir\'s System.cmd with a list of arguments instead of string interpolation. Validate and sanitize all user inputs in Phoenix applications',
        examples: {
            vulnerable: 'System.shell("rm -rf #{path}")',
            secure: 'System.cmd("rm", ["-rf", path])'
        }
    },
    {
        id: 'elixir-xss-raw-html',
        type: types_js_1.VulnerabilityType.XSS,
        name: 'XSS via Phoenix Raw HTML Output',
        description: 'Detects XSS vulnerabilities from raw HTML output in Phoenix templates',
        patterns: {
            regex: [
                /<%=\s*raw\s+[^%>]+%>/gi,
                /Phoenix\.HTML\.raw\s*\(/gi,
                /~E["'][^"']*#\{[^}]+\}[^"']*["']/gi,
                /content_tag\s*\([^,]+,\s*raw\s*\(/gi
            ]
        },
        severity: 'high',
        cweId: 'CWE-79',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['elixir'],
        remediation: 'Use Phoenix HTML escaping by default. Only use raw() when absolutely necessary and ensure content is sanitized',
        examples: {
            vulnerable: '<%= raw user_content %>',
            secure: '<%= user_content %>'
        }
    },
    {
        id: 'elixir-weak-crypto-hash',
        type: types_js_1.VulnerabilityType.BROKEN_AUTHENTICATION,
        name: 'Weak Password Hashing in Elixir',
        description: 'Detects use of weak hashing algorithms for passwords',
        patterns: {
            regex: [
                /:crypto\.hash\s*\(\s*:(?:md5|sha|sha1|sha256)\s*,/gi,
                /Base\.encode\d+\s*\(\s*:crypto\.hash\s*\(\s*:(?:md5|sha|sha1|sha256)\s*,/gi,
                /Bcrypt\.hash_pwd_salt\s*\([^,)]+,\s*log_rounds:\s*[1-7]\b/gi,
                /:crypto\.hash\s*\(\s*:sha256\s*,[^)]*password/gi,
                /:crypto\.hash\s*\(\s*:sha\s*,\s*password/gi
            ]
        },
        severity: 'high',
        cweId: 'CWE-916',
        owaspCategory: 'A07:2021 - Identification and Authentication Failures',
        languages: ['elixir'],
        remediation: 'Use Bcrypt, Argon2, or Pbkdf2 with appropriate cost factors in Elixir. For Bcrypt, use at least 12 rounds with the bcrypt_elixir library',
        examples: {
            vulnerable: ':crypto.hash(:md5, password)',
            secure: 'Bcrypt.hash_pwd_salt(password, log_rounds: 12)'
        }
    },
    {
        id: 'elixir-hardcoded-secrets',
        type: types_js_1.VulnerabilityType.HARDCODED_SECRETS,
        name: 'Hardcoded Secrets in Elixir',
        description: 'Detects hardcoded API keys and secrets',
        patterns: {
            regex: [
                /@(?:api_key|secret_key|jwt_secret|private_key)\s+["'][^"']{16,}["']/gi,
                /config\s+:[^,]+,\s*(?:api_key|secret_key|password):\s*["'][^"']{8,}["']/gi,
                /defp?\s+(?:secret_key|api_key|password)\s*(?:\(\))?,\s*do:\s*["'][^"']{8,}["']/gi,
                /["'](?:sk|pk|api|key)_(?:live|test)_[a-zA-Z0-9]{16,}["']/gi
            ]
        },
        severity: 'high',
        cweId: 'CWE-798',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
        languages: ['elixir'],
        remediation: 'Use environment variables or Elixir\'s configuration system. Never hardcode secrets in source code. Use System.get_env/1 for Phoenix apps',
        examples: {
            vulnerable: '@api_key "sk_live_4242424242424242"',
            secure: '@api_key System.get_env("API_KEY")'
        }
    },
    {
        id: 'elixir-sensitive-data-logging',
        type: types_js_1.VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
        name: 'Sensitive Data in Logs',
        description: 'Detects logging of sensitive information',
        patterns: {
            regex: [
                /Logger\.(?:info|debug|warn|error)\s*\([^)]*(?:password|credit_card|ssn|api_key)[^)]*#\{[^}]+\}/gi,
                /IO\.inspect\s*\([^,)]*(?:password|credit_card|ssn|api_key)[^,)]*,/gi,
                /require\s+Logger[^;]*Logger\.(?:info|debug)\s*\([^)]*#\{[^}]+\}[^)]*(?:password|SSN|credit)/gi
            ]
        },
        severity: 'medium',
        cweId: 'CWE-532',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
        languages: ['elixir'],
        remediation: 'Never log sensitive data in Elixir applications. Use structured logging with Logger and filter out sensitive fields in Phoenix',
        examples: {
            vulnerable: 'Logger.info("User password: #{password}")',
            secure: 'Logger.info("User authenticated", user_id: user.id)'
        }
    },
    {
        id: 'elixir-unsafe-atom-creation',
        type: types_js_1.VulnerabilityType.INSECURE_DESERIALIZATION,
        name: 'Unsafe Atom Creation',
        description: 'Detects dynamic atom creation from user input which can lead to memory exhaustion',
        patterns: {
            regex: [
                /String\.to_atom\s*\(/gi,
                /:"#\{[^}]+\}"/gi,
                /List\.to_atom\s*\(/gi,
                /:erlang\.binary_to_atom\s*\(/gi
            ]
        },
        severity: 'medium',
        cweId: 'CWE-502',
        owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
        languages: ['elixir'],
        remediation: 'Use Elixir\'s String.to_existing_atom/1 instead or validate against a whitelist of allowed atoms in Elixir applications',
        examples: {
            vulnerable: 'String.to_atom(user_input)',
            secure: 'String.to_existing_atom(user_input)'
        }
    },
    {
        id: 'elixir-code-evaluation',
        type: types_js_1.VulnerabilityType.INSECURE_DESERIALIZATION,
        name: 'Unsafe Code Evaluation',
        description: 'Detects dynamic code evaluation vulnerabilities',
        patterns: {
            regex: [
                /Code\.eval_string\s*\(/gi,
                /Code\.eval_quoted\s*\(/gi,
                /apply\s*\([^,]+,\s*String\.to_atom\s*\(/gi
            ]
        },
        severity: 'critical',
        cweId: 'CWE-94',
        owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
        languages: ['elixir'],
        remediation: 'Avoid dynamic code evaluation in Elixir. If necessary, strictly validate and sandbox the execution using proper Elixir patterns',
        examples: {
            vulnerable: 'Code.eval_string(user_input)',
            secure: 'case user_input do\n  "allowed_function" -> allowed_function()\n  _ -> {:error, "Invalid function"}\nend'
        }
    },
    {
        id: 'elixir-cors-misconfiguration',
        type: types_js_1.VulnerabilityType.SECURITY_MISCONFIGURATION,
        name: 'CORS Misconfiguration',
        description: 'Detects overly permissive CORS configurations',
        patterns: {
            regex: [
                /plug\s+CORSPlug\s*,\s*origin:\s*["']\*["']/gi,
                /put_resp_header\s*\([^,]+,\s*["']access-control-allow-origin["']\s*,\s*["']\*["']/gi,
                /config\s+:cors_plug\s*,\s*origin:\s*\[["']\*["']\]/gi
            ]
        },
        severity: 'medium',
        cweId: 'CWE-942',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        languages: ['elixir'],
        remediation: 'Configure CORS with specific allowed origins instead of wildcards in Phoenix applications using CORSPlug',
        examples: {
            vulnerable: 'plug CORSPlug, origin: "*"',
            secure: 'plug CORSPlug, origin: ["https://trusted-domain.com"]'
        }
    },
    {
        id: 'elixir-debug-mode-enabled',
        type: types_js_1.VulnerabilityType.DEBUG_MODE,
        name: 'Debug Mode Enabled',
        description: 'Detects debug configurations that should not be in production',
        patterns: {
            regex: [
                /config\s+:[^,]+,\s*[^,\n]*debug_errors:\s*true/gi,
                /config\s+:phoenix\s*,\s*:stacktrace_depth\s*,\s*\d{2,}/gi,
                /config\s+:logger\s*,\s*level:\s*:debug/gi,
                /debug_errors:\s*true/gi
            ]
        },
        severity: 'medium',
        cweId: 'CWE-489',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        languages: ['elixir'],
        remediation: 'Ensure debug mode is disabled in production configurations for Phoenix and Elixir applications',
        examples: {
            vulnerable: 'config :my_app, MyApp.Endpoint, debug_errors: true',
            secure: 'config :my_app, MyApp.Endpoint, debug_errors: false'
        }
    },
    {
        id: 'elixir-ssrf-vulnerability',
        type: types_js_1.VulnerabilityType.SSRF,
        name: 'Server-Side Request Forgery',
        description: 'Detects SSRF vulnerabilities in HTTP clients',
        patterns: {
            regex: [
                /HTTPoison\.get!?\s*\(\s*params\[["'][^"']+["']\]/gi,
                /Tesla\.get!?\s*\([^)]*user_provided[^)]*\)/gi,
                /:httpc\.request\s*\([^)]*binary_to_list\s*\([^)]*url[^)]*\)/gi,
                /Req\.get!?\s*\(\s*params\[["'][^"']+["']\]/gi
            ]
        },
        severity: 'high',
        cweId: 'CWE-918',
        owaspCategory: 'A10:2021 - Server-Side Request Forgery',
        languages: ['elixir'],
        remediation: 'Validate and whitelist URLs before making requests in Elixir. Use URI module in Elixir to parse and verify the domain',
        examples: {
            vulnerable: 'HTTPoison.get(params["url"])',
            secure: 'if URI.parse(url).host in @allowed_hosts, do: HTTPoison.get(url)'
        }
    },
    {
        id: 'elixir-weak-random',
        type: types_js_1.VulnerabilityType.WEAK_CRYPTOGRAPHY,
        name: 'Weak Random Number Generation',
        description: 'Detects use of weak random number generators for security purposes',
        patterns: {
            regex: [
                /:rand\.uniform\s*\(/gi,
                /Enum\.random\s*\(/gi,
                /:random\.uniform\s*\(/gi,
                /System\.unique_integer\s*\([^)]*\)\s*\|>\s*rem\s*\(/gi
            ]
        },
        severity: 'medium',
        cweId: 'CWE-338',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
        languages: ['elixir'],
        remediation: 'Use Elixir\'s :crypto.strong_rand_bytes/1 for cryptographically secure random values instead of weak generators',
        examples: {
            vulnerable: ':rand.uniform(1000000)',
            secure: ':crypto.strong_rand_bytes(4) |> :binary.decode_unsigned()'
        }
    },
    {
        id: 'elixir-csrf-protection-disabled',
        type: types_js_1.VulnerabilityType.CSRF,
        name: 'CSRF Protection Disabled',
        description: 'Detects disabled or misconfigured CSRF protection',
        patterns: {
            regex: [
                /plug\s+:protect_from_forgery\s*,\s*except:\s*\[[^\]]+\]/gi,
                /#\s*plug\s+:protect_from_forgery/gi,
                /pipeline\s+:api\s+do[^}]*plug\s+:accepts\s*,\s*\[["']json["']\][^}]*end/gi
            ]
        },
        severity: 'medium',
        cweId: 'CWE-352',
        owaspCategory: 'A01:2021 - Broken Access Control',
        languages: ['elixir'],
        remediation: 'Enable CSRF protection in Phoenix for all state-changing operations. For APIs, use proper authentication tokens with plug',
        examples: {
            vulnerable: 'plug :protect_from_forgery, except: [:create, :update]',
            secure: 'plug :protect_from_forgery'
        }
    },
    {
        id: 'elixir-insufficient-logging',
        type: types_js_1.VulnerabilityType.INSUFFICIENT_LOGGING,
        name: 'Missing Security Event Logging',
        description: 'Detects missing logging for security-critical operations',
        patterns: {
            regex: [
                /def\s+(?:authenticate|login|authorize)[^}]*end(?!.*Logger)/gi,
                /case\s+.*authenticate.*\s+do[^}]*{:error[^}]*->(?!.*Logger)/gi
            ]
        },
        severity: 'low',
        cweId: 'CWE-778',
        owaspCategory: 'A09:2021 - Security Logging and Monitoring Failures',
        languages: ['elixir'],
        remediation: 'Add comprehensive logging in Elixir for all security-critical operations including authentication, authorization, and sensitive data access using Logger',
        examples: {
            vulnerable: 'def authenticate(user, password) do\n  # authentication logic\nend',
            secure: 'def authenticate(user, password) do\n  result = # authentication logic\n  Logger.info("Authentication attempt", user_id: user.id, success: result != nil)\n  result\nend'
        }
    },
    {
        id: 'elixir-xml-external-entities',
        type: types_js_1.VulnerabilityType.XML_EXTERNAL_ENTITIES,
        name: 'XML External Entity Injection',
        description: 'Detects potential XXE vulnerabilities in XML parsing',
        patterns: {
            regex: [
                /:xmerl_scan\.string\s*\(/gi,
                /SweetXml\.parse\s*\([^,)]+\)/gi,
                /:erlang\.binary_to_term\s*\([^,)]+,\s*\[\s*:safe\s*\]\)/gi
            ]
        },
        severity: 'high',
        cweId: 'CWE-611',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        languages: ['elixir'],
        remediation: 'Disable external entity processing in Elixir XML parsers. Use SweetXml or other safe Elixir XML parsing libraries with XXE protection enabled by default',
        examples: {
            vulnerable: ':xmerl_scan.string(xml_content)',
            secure: 'SweetXml.parse(xml_content, dtd: :none)'
        }
    },
    {
        id: 'elixir-path-traversal',
        type: types_js_1.VulnerabilityType.PATH_TRAVERSAL,
        name: 'Path Traversal Vulnerability',
        description: 'Detects path traversal vulnerabilities in file operations',
        patterns: {
            regex: [
                /File\.read!?\s*\([^)]*#\{[^}]+\}/gi,
                /Path\.join\s*\([^,)]+,\s*[^)]*params\[/gi,
                /File\.open!?\s*\([^)]*\.\.\//gi
            ]
        },
        severity: 'high',
        cweId: 'CWE-22',
        owaspCategory: 'A01:2021 - Broken Access Control',
        languages: ['elixir'],
        remediation: 'Validate and sanitize file paths in Elixir. Use Path.expand/2 with a safe base directory and verify the result stays within allowed paths in Phoenix',
        examples: {
            vulnerable: 'File.read!("/uploads/#{params["filename"]}")',
            secure: 'safe_path = Path.expand(params["filename"], "/uploads")\nif String.starts_with?(safe_path, "/uploads/"), do: File.read!(safe_path)'
        }
    },
    {
        id: 'elixir-ldap-injection',
        type: types_js_1.VulnerabilityType.LDAP_INJECTION,
        name: 'LDAP Injection',
        description: 'Detects LDAP injection vulnerabilities',
        patterns: {
            regex: [
                /:eldap\.search\s*\([^)]*filter:[^)]*#\{[^}]+\}/gi,
                /filter\s*=\s*["'][^"']*#\{[^}]+\}[^"']*["']/gi
            ]
        },
        severity: 'high',
        cweId: 'CWE-90',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['elixir'],
        remediation: 'Use Elixir LDAP libraries that support parameterized queries or properly escape special LDAP characters in user input for Phoenix apps',
        examples: {
            vulnerable: ':eldap.search(handle, base: base_dn, filter: {:equalityMatch, {:AttributeValueAssertion, "uid", "#{username}"}})',
            secure: ':eldap.search(handle, base: base_dn, filter: {:equalityMatch, {:AttributeValueAssertion, "uid", Eldap.escape(username)}})'
        }
    },
    {
        id: 'elixir-nosql-injection',
        type: types_js_1.VulnerabilityType.NOSQL_INJECTION,
        name: 'NoSQL Injection in MongoDB',
        description: 'Detects NoSQL injection vulnerabilities in MongoDB queries',
        patterns: {
            regex: [
                /Mongo\.find\s*\([^,)]+,\s*%\{[^}]*#\{[^}]+\}/gi,
                /\$where:[^,}]*#\{[^}]+\}/gi
            ]
        },
        severity: 'high',
        cweId: 'CWE-943',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['elixir'],
        remediation: 'Avoid using string interpolation in NoSQL queries from Elixir. Use parameterized queries and validate input types with Ecto',
        examples: {
            vulnerable: 'Mongo.find(:mongo, "users", %{username: "#{username}", password: "#{password}"})',
            secure: 'Mongo.find(:mongo, "users", %{username: username, password: password})'
        }
    },
    {
        id: 'elixir-broken-access-control',
        type: types_js_1.VulnerabilityType.BROKEN_ACCESS_CONTROL,
        name: 'Missing Authorization Check',
        description: 'Detects missing authorization checks in Phoenix controllers',
        patterns: {
            regex: [
                /def\s+(?:delete|update|edit)\s*\([^)]+\)\s+do(?!.*authorize|.*can\?|.*policy)/gi,
                /resources\s+["']\/admin/gi
            ]
        },
        severity: 'high',
        cweId: 'CWE-862',
        owaspCategory: 'A01:2021 - Broken Access Control',
        languages: ['elixir'],
        remediation: 'Implement proper authorization checks in Phoenix using Elixir libraries like Canada or Bodyguard. Always verify user permissions before allowing access to resources',
        examples: {
            vulnerable: 'def delete(conn, %{"id" => id}) do\n  User.get!(id) |> Repo.delete()\nend',
            secure: 'def delete(conn, %{"id" => id}) do\n  user = User.get!(id)\n  authorize!(conn.assigns.current_user, :delete, user)\n  Repo.delete(user)\nend'
        }
    },
    {
        id: 'elixir-template-injection',
        type: types_js_1.VulnerabilityType.TEMPLATE_INJECTION,
        name: 'Template Injection',
        description: 'Detects template injection vulnerabilities in EEx templates',
        patterns: {
            regex: [
                /EEx\.eval_string\s*\([^,)]*user/gi,
                /Code\.eval_string\s*\([^)]*template/gi
            ]
        },
        severity: 'high',
        cweId: 'CWE-94',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['elixir'],
        remediation: 'Never evaluate user-provided templates in Elixir. Use static EEx templates in Phoenix and pass data as variables',
        examples: {
            vulnerable: 'EEx.eval_string(user_template, assigns: data)',
            secure: 'EEx.eval_file("templates/safe_template.eex", assigns: data)'
        }
    },
    {
        id: 'elixir-vulnerable-components',
        type: types_js_1.VulnerabilityType.VULNERABLE_COMPONENTS,
        name: 'Use of Vulnerable Dependencies',
        description: 'Detects potentially vulnerable Elixir/Erlang functions',
        patterns: {
            regex: [
                /:erlang\.now\s*\(\)/gi,
                /:random\./gi,
                /:erlang\.binary_to_term\s*\([^,)]+\)(?!\s*,\s*\[\s*:safe\s*\])/gi
            ]
        },
        severity: 'medium',
        cweId: 'CWE-1104',
        owaspCategory: 'A06:2021 - Vulnerable and Outdated Components',
        languages: ['elixir'],
        remediation: 'Use modern Elixir alternatives: System.monotonic_time instead of :erlang.now, :rand instead of :random, and always use safe option with binary_to_term',
        examples: {
            vulnerable: ':erlang.now()',
            secure: 'System.monotonic_time()'
        }
    },
    {
        id: 'elixir-denial-of-service',
        type: types_js_1.VulnerabilityType.DENIAL_OF_SERVICE,
        name: 'Potential DoS via Atom Exhaustion',
        description: 'Detects patterns that could lead to atom table exhaustion',
        patterns: {
            regex: [
                /String\.to_atom\s*\([^)]*user/gi,
                /for\s+[^<]+<-[^,]+,\s+do:\s+String\.to_atom/gi
            ]
        },
        severity: 'medium',
        cweId: 'CWE-400',
        owaspCategory: 'A06:2021 - Vulnerable and Outdated Components',
        languages: ['elixir'],
        remediation: 'Atoms are not garbage collected in Elixir. Use String.to_existing_atom/1 or maintain a whitelist of allowed atoms in Phoenix',
        examples: {
            vulnerable: 'Enum.map(user_inputs, &String.to_atom/1)',
            secure: 'Enum.map(user_inputs, &String.to_existing_atom/1)'
        }
    },
    {
        id: 'elixir-open-redirect',
        type: types_js_1.VulnerabilityType.OPEN_REDIRECT,
        name: 'Open Redirect Vulnerability',
        description: 'Detects open redirect vulnerabilities in Phoenix applications',
        patterns: {
            regex: [
                /redirect\s*\(\s*conn\s*,\s*external:\s*[^)]*params/gi,
                /redirect\s*\(\s*conn\s*,\s*to:\s*params\[/gi
            ]
        },
        severity: 'medium',
        cweId: 'CWE-601',
        owaspCategory: 'A01:2021 - Broken Access Control',
        languages: ['elixir'],
        remediation: 'Validate redirect URLs against a whitelist in Phoenix. Never redirect to user-provided URLs without validation in Elixir web apps',
        examples: {
            vulnerable: 'redirect(conn, external: params["redirect_to"])',
            secure: 'if URI.parse(url).host == "trusted.com", do: redirect(conn, external: url)'
        }
    },
    {
        id: 'elixir-information-disclosure',
        type: types_js_1.VulnerabilityType.INFORMATION_DISCLOSURE,
        name: 'Information Disclosure in Error Messages',
        description: 'Detects potential information disclosure through error messages',
        patterns: {
            regex: [
                /render\s*\(\s*conn\s*,\s*["']error["']\s*,\s*error:\s*inspect\s*\(/gi,
                /json\s*\(\s*conn\s*,\s*%\{error:\s*Exception\.message\s*\(/gi
            ]
        },
        severity: 'low',
        cweId: 'CWE-209',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        languages: ['elixir'],
        remediation: 'Return generic error messages to users in Phoenix. Log detailed errors server-side only using Elixir Logger',
        examples: {
            vulnerable: 'json(conn, %{error: Exception.message(e)})',
            secure: 'Logger.error("Error details: #{Exception.message(e)}")\njson(conn, %{error: "An error occurred"})'
        }
    },
    {
        id: 'elixir-insecure-design',
        type: types_js_1.VulnerabilityType.IMPROPER_INPUT_VALIDATION,
        name: 'Improper Input Validation',
        description: 'Detects missing input validation in Elixir/Phoenix applications',
        patterns: {
            regex: [
                /cast\s*\(\s*[^,]+,\s*[^,]+,\s*\[[^\]]*:admin[^\]]*\]\s*\)/gi,
                /String\.to_integer\s*\([^)]*params/gi,
                /File\.read!\s*\([^)]*params\[/gi
            ]
        },
        severity: 'medium',
        cweId: 'CWE-20',
        owaspCategory: 'A04:2021 - Insecure Design',
        languages: ['elixir'],
        remediation: 'Always validate and sanitize user input. Use Ecto changesets with proper validations. Never trust user input directly',
        examples: {
            vulnerable: 'String.to_integer(params["age"])',
            secure: 'case Integer.parse(params["age"] || "") do\n  {age, ""} when age > 0 and age < 150 -> age\n  _ -> {:error, "Invalid age"}\nend'
        }
    }
];
exports.default = exports.elixirSecurityPatterns;
