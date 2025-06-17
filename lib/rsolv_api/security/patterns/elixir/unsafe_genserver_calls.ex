defmodule RsolvApi.Security.Patterns.Elixir.UnsafeGenserverCalls do
  @moduledoc """
  Unsafe GenServer Calls vulnerability pattern for Elixir/OTP applications.

  This pattern detects GenServer calls that execute arbitrary commands or code 
  based on user input, potentially enabling remote code execution and process 
  hijacking attacks in BEAM applications.

  ## Vulnerability Details

  Unsafe GenServer calls occur when applications process untrusted input through
  GenServer message handlers without proper validation:
  - GenServer.call with :execute, :run, or :eval commands from user input
  - Dynamic command construction using String.to_atom or interpolation
  - Unvalidated message passing to GenServer handlers
  - Process commands that directly execute user-provided code or system calls

  ## Technical Impact

  Security risks through GenServer exploitation:
  - Remote code execution through arbitrary command execution in BEAM VM
  - Process hijacking by injecting malicious GenServer messages
  - System compromise via unvalidated system command execution
  - Resource exhaustion through malicious GenServer call patterns

  ## Examples

  Vulnerable patterns:
  ```elixir
  # VULNERABLE - Direct execution of user commands
  GenServer.call(pid, {:execute, user_command})
  
  # VULNERABLE - Dynamic command from user input
  GenServer.call(server, {String.to_atom(cmd), args})
  
  # VULNERABLE - Unvalidated code evaluation
  def handle_call({:eval, code}, _from, state) do
    result = Code.eval_string(code)
    {:reply, result, state}
  end
  
  # VULNERABLE - Direct message passing
  GenServer.call(worker, untrusted_message)
  ```

  Safe alternatives:
  ```elixir
  # SAFE - Whitelist of allowed commands
  case command do
    "status" -> GenServer.call(pid, :get_status)
    "restart" -> GenServer.call(pid, :restart)
    _ -> {:error, :invalid_command}
  end
  
  # SAFE - Validated command execution
  case validate_command(user_command) do
    {:ok, :status} -> GenServer.call(pid, :get_status)
    {:ok, :update, data} -> GenServer.call(pid, {:update, data})
    :error -> {:error, :invalid_command}
  end
  
  # SAFE - Pattern matching in handler
  def handle_call({:increment, n}, _from, state) when is_integer(n) do
    {:reply, :ok, state + n}
  end
  ```

  ## Attack Scenarios

  1. **Remote Code Execution**: Attacker sends malicious code through API that 
     gets executed via GenServer.call(pid, {:execute, malicious_code})

  2. **Process Hijacking**: Attacker injects commands to take control of 
     GenServer processes and manipulate application state

  3. **System Command Injection**: User input flows to GenServer handlers that 
     execute system commands without validation

  ## References

  - CWE-94: Improper Control of Generation of Code ('Code Injection')
  - OWASP Top 10 2021 - A03: Injection
  - Erlang/OTP Security Guidelines
  - BEAM VM Security Best Practices
  """

  use RsolvApi.Security.Patterns.PatternBase

  @impl true
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "elixir-unsafe-genserver-calls",
      name: "Unsafe GenServer Calls",
      description: "GenServer calls with unvalidated user input enable remote code execution attacks",
      type: :rce,
      severity: :medium,
      languages: ["elixir"],
      frameworks: ["otp"],
      regex: [
        # GenServer.call with execute/run/eval commands - exclude safe_command variables
        ~r/^(?!\s*#)(?!\s*@doc)(?!.*safe_command)(?!.*validated_)(?!.*checked_).*GenServer\.call\s*\(\s*[^,]+\s*,\s*\{\s*:(?:execute|run|eval|run_code|eval_string|run_command|execute_code)/m,
        
        # GenServer.call with dynamic atom interpolation
        ~r/^(?!\s*#)(?!\s*@doc).*GenServer\.call\s*\(\s*[^,]+\s*,\s*\{\s*:"#\{/m,
        
        # GenServer.call with String.to_atom
        ~r/^(?!\s*#)(?!\s*@doc).*GenServer\.call\s*\(\s*[^,]+\s*,\s*\{String\.to_atom/m,
        
        # GenServer.call with variable message (untrusted) - exclude safe variables
        ~r/^(?!\s*#)(?!\s*@doc).*GenServer\.call\s*\(\s*[^,]+\s*,\s*(?:request|untrusted_message|user_input|params)\s*[,)]/m,
        
        # handle_call with execute/run/eval patterns
        ~r/^(?!\s*#)(?!\s*@doc).*def\s+handle_call\s*\(\s*\{\s*:(?:execute|run|eval|run_code|eval_string|run_command|execute_code)/m,
        
        # GenServer.call with tuple variable - exclude safe variable names
        ~r/^(?!\s*#)(?!\s*@doc).*GenServer\.call\s*\(\s*[^,]+\s*,\s*\{[^:}][^,}]*,\s*(?!safe_|validated_|checked_)(?:user_input|input|cmd|command|code)/m
      ],
      default_tier: :protected,
      cwe_id: "CWE-94",
      owasp_category: "A03:2021",
      recommendation: "Validate and whitelist all GenServer commands, never execute user input directly",
      test_cases: %{
        vulnerable: [
          ~S|GenServer.call(pid, {:execute, user_command})|,
          ~S|GenServer.call(server, {:run, params["code"]})|,
          ~S|GenServer.call(MyServer, {String.to_atom(cmd), args})|,
          ~S|def handle_call({:eval, code}, _from, state) do|
        ],
        safe: [
          ~S|GenServer.call(pid, :get_state)|,
          ~S|GenServer.call(server, {:increment, 1})|,
          ~S"""
          case validate_command(cmd) do
            {:ok, :status} -> GenServer.call(pid, :get_status)
            :error -> {:error, :invalid_command}
          end
          """,
          ~S|def handle_call(:get_status, _from, state) do|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      attack_vectors: """
      1. Remote code execution by sending malicious commands through GenServer.call with execute/eval operations
      2. Process hijacking via injection of arbitrary GenServer messages to manipulate process state
      3. System command injection through GenServer handlers that execute unvalidated shell commands
      4. Atom exhaustion attacks using dynamic atom creation from user input in GenServer calls
      5. Denial of service through malicious GenServer call patterns causing process crashes or hangs
      """,
      business_impact: """
      Medium: Unsafe GenServer calls can result in:
      - System compromise through remote code execution in application processes
      - Data breaches via unauthorized access to process state and sensitive information
      - Service disruption through process crashes and resource exhaustion attacks
      - Operational risk from attackers manipulating critical business logic
      - Compliance violations due to unauthorized code execution capabilities
      """,
      technical_impact: """
      Medium: GenServer exploitation enables:
      - Remote code execution within BEAM VM processes allowing arbitrary operations
      - Process state manipulation through injected GenServer messages and commands
      - System command execution via vulnerable GenServer handlers
      - Resource exhaustion through malicious call patterns and atom table pollution
      - Privilege escalation by hijacking processes with elevated permissions
      """,
      likelihood: "Medium: GenServer patterns are common in Elixir/OTP applications and input validation is often overlooked",
      cve_examples: [
        "CWE-94: Improper Control of Generation of Code",
        "CWE-78: OS Command Injection via GenServer handlers",
        "CWE-502: Deserialization of Untrusted Data in BEAM",
        "OWASP Top 10 A03:2021 - Injection"
      ],
      compliance_standards: [
        "OWASP Top 10 2021 - A03: Injection",
        "NIST Cybersecurity Framework - SI-10: Information Input Validation",
        "ISO 27001 - A.14.2: Security in development and support processes",
        "PCI DSS - Requirement 6.5.1: Injection flaws, particularly SQL injection"
      ],
      remediation_steps: """
      1. Implement strict whitelist validation for all GenServer commands
      2. Use pattern matching in handle_call to limit allowed operations
      3. Never construct GenServer messages dynamically from user input
      4. Validate all parameters before passing to GenServer.call
      5. Use predefined atoms instead of String.to_atom for commands
      6. Implement authorization checks in GenServer handlers
      """,
      prevention_tips: """
      1. Always validate and whitelist GenServer commands before execution
      2. Use pattern matching to restrict handle_call to known safe operations
      3. Never use String.to_atom or dynamic atom creation with user input
      4. Implement proper authorization in GenServer message handlers
      5. Use typed contracts and guards to enforce input constraints
      6. Avoid passing raw user input directly to GenServer.call
      """,
      detection_methods: """
      1. Static code analysis for GenServer.call patterns with user input
      2. Code review focusing on GenServer message handling and validation
      3. Dynamic testing with malicious GenServer messages
      4. Security scanning tools checking for code injection patterns
      5. Runtime monitoring of GenServer call patterns and payloads
      """,
      safe_alternatives: """
      1. Command whitelisting: validate_command(cmd) with predefined allowed commands
      2. Pattern matching handlers: def handle_call(:known_command, _, state)
      3. Typed message structs: defstruct [:action, :data] with validation
      4. Authorization middleware: check_permission before GenServer.call
      5. Safe command mapping: Map.get(allowed_commands, user_input, :invalid)
      6. Parameterized queries: separate command from data in GenServer messages
      """
    }
  end

  @impl true  
  def ast_enhancement do
    %{
      min_confidence: 0.7,
      context_rules: %{
        unsafe_commands: [
          "execute", "run", "eval", "run_code", "eval_string", 
          "run_command", "execute_code", "system", "cmd"
        ],
        genserver_functions: [
          "GenServer.call", "GenServer.cast", "GenServer.multi_call",
          ":gen_server.call", ":gen_server.cast"
        ],
        user_input_indicators: [
          "params", "user_input", "input", "cmd", "command", 
          "code", "request", "untrusted", "data"
        ],
        safe_commands: [
          "get_state", "get_status", "increment", "decrement",
          "update", "fetch", "list", "count"
        ],
        exclude_comments: true,
        exclude_doc_attributes: true,
        exclude_if_within_case: true,
        exclude_if_validation_present: true,
        validation_patterns: [
          "validate_command",
          "validate_",
          "sanitize_",
          "check_",
          "verify_"
        ]
      },
      confidence_rules: %{
        base: 0.7,
        adjustments: %{
          unsafe_command_bonus: 0.3,
          user_input_bonus: 0.2,
          validated_command_penalty: -0.8,
          pattern_match_penalty: -0.7,
          whitelist_check_penalty: -0.9,
          safe_command_penalty: -0.6
        }
      },
      ast_rules: %{
        node_type: "genserver_call_analysis",
        genserver_analysis: %{
          check_call_patterns: true,
          genserver_functions: ["GenServer.call", "GenServer.cast"],
          check_command_construction: true,
          detect_dynamic_atoms: true
        },
        command_analysis: %{
          check_command_names: true,
          unsafe_command_patterns: ["execute", "run", "eval"],
          check_user_input_flow: true,
          detect_string_to_atom: true
        },
        validation_analysis: %{
          check_validation_presence: true,
          validation_patterns: ["validate", "check", "verify", "whitelist"],
          check_pattern_matching: true,
          detect_guard_clauses: true
        }
      }
    }
  end
end