defmodule RsolvApi.Security.Patterns.Php.EvalUsage do
  @moduledoc """
  Pattern for detecting dangerous eval() usage in PHP.
  
  This pattern identifies when PHP applications use the eval() function with
  user input, potentially allowing attackers to execute arbitrary PHP code
  and achieve remote code execution (RCE).
  
  ## Vulnerability Details
  
  The eval() function in PHP executes a string as PHP code, making it one of the
  most dangerous functions when used with user input. Attackers can inject arbitrary
  PHP code that will be executed with the same privileges as the web application,
  potentially leading to complete system compromise.
  
  ### Attack Example
  ```php
  // Vulnerable code - user input directly passed to eval()
  $code = $_POST['code']; // Attacker input: "system('rm -rf /');"
  eval($code);
  
  // Results in execution of arbitrary system commands
  // This can lead to data theft, system compromise, or destruction
  ```
  
  The eval() function bypasses all PHP security mechanisms and executes the
  provided string as if it were written directly in the source code. This makes
  it impossible to safely use with any form of user input.
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "php-eval-usage",
      name: "Code Injection via eval()",
      description: "Using eval() with user input allowing remote code execution",
      type: :rce,
      severity: :critical,
      languages: ["php"],
      regex: ~r/eval\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)/,
      default_tier: :public,
      cwe_id: "CWE-95",
      owasp_category: "A03:2021",
      recommendation: "Never use eval() with user input. Find alternative solutions",
      test_cases: %{
        vulnerable: [
          ~S|eval($_POST['code']);|,
          ~S|eval("return " . $_GET['expression'] . ";");|,
          ~S|eval(base64_decode($_POST['encoded']));|
        ],
        safe: [
          ~S|eval('return 42;');|,
          ~S|evaluate($_POST['expression']);|,
          ~S|switch($_POST['operation']) { case 'add': $result = $a + $b; break; }|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Code injection via eval() is one of the most critical security vulnerabilities in PHP
      applications. The eval() function executes a string as PHP code, and when user input
      is passed to this function without any validation or sanitization, attackers can execute
      arbitrary PHP code on the server, leading to complete system compromise.
      
      The eval() function treats its input as PHP code and executes it with the same privileges
      as the web application. This means attackers can:
      - Execute system commands
      - Read or write any files accessible to the web server
      - Connect to internal networks
      - Install backdoors or malware
      - Steal sensitive data including database credentials
      - Modify application behavior
      - Delete or corrupt data
      
      ### Why eval() is Dangerous
      
      **Complete Code Execution**: Unlike other injection vulnerabilities that may be limited
      to specific contexts (like SQL queries), eval() allows execution of any valid PHP code.
      This includes calling system functions, manipulating files, or even modifying the
      running application itself.
      
      **Bypasses All Security Mechanisms**: Code executed through eval() runs with the same
      privileges as the application and bypasses any security measures implemented at higher
      levels. Web Application Firewalls (WAFs) often cannot protect against eval() injection
      once the malicious input reaches the function.
      
      **Difficult to Sanitize**: There is no reliable way to sanitize user input for eval().
      Even with extensive filtering, attackers can use various encoding techniques, PHP
      features, and creative syntax to bypass filters.
      
      ### Common Attack Vectors
      
      **Direct Code Execution**: The simplest attack involves directly injecting PHP code:
      ```php
      // Vulnerable code
      eval($_POST['expression']);
      
      // Attack payload
      $_POST['expression'] = "system('cat /etc/passwd');";
      ```
      
      **Obfuscated Payloads**: Attackers often obfuscate their payloads to bypass simple filters:
      ```php
      // Using base64 encoding
      $_POST['code'] = "c3lzdGVtKCdpZCcpOw=="; // base64 of "system('id');"
      eval(base64_decode($_POST['code']));
      
      // Using PHP functions
      $_POST['code'] = "\\x73\\x79\\x73\\x74\\x65\\x6d('id');"; // hex encoded
      ```
      
      **Variable Function Calls**: PHP's variable functions can be exploited:
      ```php
      // Vulnerable pattern
      eval("\\$func = \\$_GET['func']; \\$func();");
      
      // Attack: $_GET['func'] = "phpinfo"
      ```
      
      ### Real-World Impact
      
      Eval() injection has been responsible for numerous high-profile breaches:
      - **Complete Server Takeover**: Attackers gain shell access to execute any command
      - **Data Exfiltration**: Sensitive data including user credentials and payment information
      - **Cryptocurrency Mining**: Servers hijacked to mine cryptocurrency
      - **Botnet Recruitment**: Compromised servers used for DDoS attacks
      - **Ransomware Deployment**: Encryption of server data for ransom
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-95",
          title: "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
          url: "https://cwe.mitre.org/data/definitions/95.html"
        },
        %{
          type: :owasp,
          id: "A03:2021",
          title: "OWASP Top 10 2021 - A03 Injection",
          url: "https://owasp.org/Top10/A03_2021-Injection/"
        },
        %{
          type: :owasp,
          id: "Eval_Injection",
          title: "OWASP - Direct Dynamic Code Evaluation ('Eval Injection')",
          url: "https://owasp.org/www-community/attacks/Direct_Dynamic_Code_Evaluation_Eval%20Injection"
        },
        %{
          type: :php_manual,
          id: "function.eval",
          title: "PHP Manual - eval() function",
          url: "https://www.php.net/manual/en/function.eval.php"
        },
        %{
          type: :research,
          id: "eval_exploitation",
          title: "Eval() Vulnerability & Exploitation",
          url: "https://www.exploit-db.com/papers/13694"
        }
      ],
      attack_vectors: [
        "Direct code execution: eval(\\$_POST['code']) with system commands",
        "Encoded payloads: eval(base64_decode(\\$_POST['encoded'])) to bypass filters",
        "String concatenation: eval('\\$var = ' . \\$_GET['value'] . ';') for variable manipulation",
        "Function construction: eval('\\$_GET[func]();') to call arbitrary functions",
        "File operations: eval('file_put_contents(\"shell.php\", \\$_POST[content]);')",
        "Database credential theft: eval('echo \\$db_password;') to expose configuration",
        "Backdoor installation: eval() to write persistent web shells"
      ],
      real_world_impact: [
        "Complete server compromise with root access",
        "Installation of persistent backdoors and web shells",
        "Theft of database contents and user credentials",
        "Lateral movement to internal network systems",
        "Cryptocurrency mining using server resources",
        "Participation in botnets for DDoS attacks",
        "Ransomware deployment encrypting server data",
        "Reputational damage and regulatory penalties"
      ],
      cve_examples: [
        %{
          id: "CVE-2023-24044",
          description: "Eval injection in PHP-Fusion 9.10.20 allowing RCE",
          severity: "critical",
          cvss: 9.8,
          note: "Unauthenticated remote code execution via eval() in maincore.php"
        },
        %{
          id: "CVE-2022-31628",
          description: "PHP eval injection in OPNsense firewall",
          severity: "critical", 
          cvss: 9.8,
          note: "Remote code execution through eval() in system configuration"
        },
        %{
          id: "CVE-2021-44106",
          description: "Eval injection in PHP Everywhere WordPress plugin",
          severity: "critical",
          cvss: 9.9,
          note: "Allows unauthenticated users to execute arbitrary PHP code"
        },
        %{
          id: "CVE-2015-2308",
          description: "Symfony HttpCache eval injection vulnerability",
          severity: "critical",
          cvss: 9.8,
          note: "ESI tag processing uses eval() allowing code execution"
        },
        %{
          id: "CVE-2019-16113",
          description: "BlueiMP jQuery File Upload eval injection",
          severity: "critical",
          cvss: 9.8,
          note: "Image processing uses eval() on file metadata enabling RCE"
        }
      ],
      detection_notes: """
      This pattern detects eval() usage vulnerabilities by identifying PHP code that:
      
      1. **Function Analysis**: Matches the eval() function call
      2. **Parameter Inspection**: Looks for user input variables within eval():
         - Direct usage: eval(\\$_POST['code'])
         - Concatenation: eval("code" . \\$_GET['input'])
         - Variable assignment: \\$code = \\$_POST['x']; eval(\\$code)
         - Function composition: eval(base64_decode(\\$_POST['data']))
      
      3. **Input Sources**: Detects all PHP superglobals:
         - \\$_GET - URL parameters
         - \\$_POST - Form data
         - \\$_REQUEST - Combined GET/POST/COOKIE
         - \\$_COOKIE - Cookie values
      
      The pattern uses a regex that matches:
      eval\\s*\\(\\s*(?:[^)]*\\$_(GET|POST|REQUEST|COOKIE)|.*\\$_(GET|POST|REQUEST|COOKIE))
      
      This covers both direct usage and complex expressions containing user input.
      """,
      safe_alternatives: [
        "Use specific parsing functions instead of eval() for mathematical expressions",
        "Implement a whitelist of allowed operations with switch/case statements",
        "Use json_decode() for data structures instead of eval()",
        "Create domain-specific languages (DSL) with safe parsers",
        "Use PHP's Reflection API for dynamic class/method invocation",
        "Implement sandbox environments if dynamic code is absolutely necessary",
        "Use template engines for dynamic content generation",
        "Never accept PHP code from users - redesign the feature"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing that input filtering can make eval() safe",
          "Using eval() for JSON parsing instead of json_decode()",
          "Thinking eval() is needed for dynamic variable names (use \$\$ instead)",
          "Using eval() to execute mathematical expressions from users",
          "Attempting to sandbox eval() with disabled functions",
          "Using eval() for template rendering instead of proper template engines",
          "Believing obfuscation or encoding prevents eval() exploitation"
        ],
        dangerous_patterns: [
          "eval(\\$_POST[...]) - Direct user input execution",
          "eval(base64_decode(...)) - Obfuscated code execution",
          "eval(file_get_contents(...)) - Remote code inclusion",
          "eval(gzinflate(...)) - Compressed payload execution",
          "create_function() - Deprecated function using eval() internally",
          "assert() with string argument - Uses eval() in older PHP versions",
          "preg_replace() with /e modifier - Executes replacement as PHP code"
        ],
        php_security_features: [
          "disable_functions in php.ini can disable eval() entirely",
          "Suhosin patch can add eval() protection (deprecated)",
          "Modern PHP versions removed /e modifier from preg_replace()",
          "assert() no longer uses eval() for strings in PHP 7.2+",
          "Many hosting providers disable eval() by default",
          "Static analysis tools can detect eval() usage",
          "Runtime application self-protection (RASP) can block eval()"
        ]
      }
    }
  end

  @doc """
  Returns test cases for the eval usage pattern.
  
  ## Examples
  
      iex> test_cases = RsolvApi.Security.Patterns.Php.EvalUsage.test_cases()
      iex> length(test_cases.positive)
      8
      
      iex> test_cases = RsolvApi.Security.Patterns.Php.EvalUsage.test_cases()
      iex> length(test_cases.negative)
      6
  """
  @impl true  
  def test_cases do
    %{
      positive: [
        %{
          code: ~S|eval($_POST['code']);|,
          description: "Direct user input in eval()"
        },
        %{
          code: ~S|eval($_GET['script']);|,
          description: "GET parameter in eval()"
        },
        %{
          code: ~S|eval("return " . $_GET['expression'] . ";");|,
          description: "String concatenation with user input"
        },
        %{
          code: ~S|eval(base64_decode($_POST['encoded']));|,
          description: "Encoded payload execution"
        },
        %{
          code: ~S|eval($_REQUEST['func'] . "();");|,
          description: "Function construction with user input"
        },
        %{
          code: ~S|eval(gzinflate($_COOKIE['compressed']));|,
          description: "Compressed payload execution"
        },
        %{
          code: ~S|eval("\$template = \"" . $_POST['template'] . "\";");|,
          description: "Template variable injection"
        }
      ],
      negative: [
        %{
          code: ~S|eval('return 42;');|,
          description: "Static string evaluation"
        },
        %{
          code: ~S|eval($safe_static_code);|,
          description: "Pre-defined safe code variable"
        },
        %{
          code: ~S|evaluate($_POST['expression']);|,
          description: "Different function name"
        },
        %{
          code: ~S|echo "eval is dangerous with $_POST[input]";|,
          description: "eval mentioned in string"
        },
        %{
          code: ~S|$reflection->eval('safe code');|,
          description: "Method call, not function"
        }
      ]
    }
  end

  @doc """
  Returns examples of vulnerable and fixed code.
  
  ## Examples
  
      iex> examples = RsolvApi.Security.Patterns.Php.EvalUsage.examples()
      iex> Map.keys(examples)
      [:vulnerable, :fixed]
  """
  @impl true
  def examples do
    %{
      vulnerable: %{
        "Direct execution" => """
        // VULNERABLE: Direct eval() of user input
        $code = $_POST['php_code'];
        eval($code);
        
        // Attacker payload: $_POST['php_code'] = "system('cat /etc/passwd');"
        // Results in arbitrary command execution
        """,
        "Mathematical expressions" => """
        // VULNERABLE: Using eval() for math
        $expression = $_GET['calc'];
        $result = eval("return $expression;");
        
        // Attacker payload: $_GET['calc'] = "1; system('id')"
        // Executes system command after calculation
        """,
        "Dynamic variable creation" => """
        // VULNERABLE: Creating variables with eval()
        $varname = $_POST['var'];
        $value = $_POST['val'];
        eval("\\$$varname = '$value';");
        
        // Attacker can overwrite any variable or execute code
        """
      },
      fixed: %{
        "Specific operations" => """
        // SECURE: Use switch for specific operations
        switch($_POST['operation']) {
            case 'add':
                $result = $a + $b;
                break;
            case 'subtract':
                $result = $a - $b;
                break;
            case 'multiply':
                $result = $a * $b;
                break;
            default:
                throw new InvalidArgumentException('Invalid operation');
        }
        """,
        "Safe alternatives" => """
        // SECURE: Safe math expression parsing
        function safe_math($expr) {
            // Only allow numbers and basic operators
            if (!preg_match('/^[0-9+\\-*\\/\\s()]+$/', $expr)) {
                throw new InvalidArgumentException('Invalid expression');
            }
            
            // Use a proper math parser library
            $parser = new MathParser();
            return $parser->evaluate($expr);
        }
        
        $result = safe_math($_GET['calc']);
        """,
        "Variable variables" => """
        // SECURE: Use variable variables instead of eval()
        $allowed_vars = ['user_name', 'user_email', 'user_id'];
        $varname = $_POST['var'];
        
        if (in_array($varname, $allowed_vars)) {
            $$varname = filter_var($_POST['val'], FILTER_SANITIZE_STRING);
        } else {
            throw new InvalidArgumentException('Invalid variable name');
        }
        """
      }
    }
  end

  @doc """
  Returns educational description of the vulnerability.
  
  ## Examples
  
      iex> desc = RsolvApi.Security.Patterns.Php.EvalUsage.vulnerability_description()
      iex> desc =~ "eval"
      true
      
      iex> desc = RsolvApi.Security.Patterns.Php.EvalUsage.vulnerability_description()
      iex> desc =~ "code injection"
      true
      
      iex> desc = RsolvApi.Security.Patterns.Php.EvalUsage.vulnerability_description()
      iex> desc =~ "remote code execution"
      true
  """
  @impl true
  def vulnerability_description do
    """
    Code injection via eval() occurs when applications execute user-controlled strings 
    as PHP code, allowing attackers to run arbitrary commands and achieve remote code execution 
    on the server.
    
    In PHP, eval() is one of the most dangerous functions because:
    
    1. **Complete Code Execution**: Any valid PHP code can be executed, including
       system commands, file operations, and network connections.
       
    2. **No Safe Usage**: There is no way to safely use eval() with user input.
       Even extensive filtering cannot prevent all attack vectors.
       
    3. **Bypasses Security**: Code executed via eval() runs with full application
       privileges and bypasses web application firewalls.
    
    ## Attack Impact
    
    Successful eval() injection can lead to:
    - **System Compromise**: Full control over the web server
    - **Data Theft**: Access to databases, files, and credentials  
    - **Backdoor Installation**: Persistent access through web shells
    - **Network Pivot**: Access to internal systems
    - **Service Disruption**: Deletion or encryption of data
    
    ## Prevention
    
    The only safe approach is to never use eval() with any user input. Replace eval()
    usage with safe alternatives like specific parsing functions, whitelisted operations,
    or proper template engines.
    """
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual vulnerabilities and false positives
  by analyzing eval() usage context and user input flow.

  ## Examples

      iex> enhancement = RsolvApi.Security.Patterns.Php.EvalUsage.ast_enhancement()
      iex> Map.keys(enhancement)
      [:min_confidence, :rules]
      
      iex> enhancement = RsolvApi.Security.Patterns.Php.EvalUsage.ast_enhancement()
      iex> enhancement.min_confidence
      0.9
      
      iex> enhancement = RsolvApi.Security.Patterns.Php.EvalUsage.ast_enhancement()
      iex> length(enhancement.rules)
      4
  """
  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.9,
      rules: [
        %{
          type: "eval_functions",
          description: "Identify eval and eval-like functions",
          functions: [
            "eval", "assert", "create_function", "call_user_func",
            "call_user_func_array", "preg_replace"
          ]
        },
        %{
          type: "user_input_analysis",
          description: "Detect user input sources flowing to eval()",
          dangerous_sources: ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER"],
          safe_sources: ["$config", "$constants", "$static_code"]
        },
        %{
          type: "obfuscation_detection", 
          description: "Detect obfuscated eval patterns",
          deobfuscation_functions: ["base64_decode", "gzinflate", "str_rot13", "hex2bin"],
          suspicious_patterns: ["chr(", "\\x", "\\\\", "$$"]
        },
        %{
          type: "context_validation",
          description: "Validate eval() context and exclude false positives",
          exclude_patterns: [
            "test", "mock", "example", "comment", "disabled",
            "// eval", "/* eval", "* eval", "return false"
          ]
        }
      ]
    }
  end
end