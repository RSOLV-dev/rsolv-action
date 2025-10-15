defmodule Rsolv.Security.Patterns.Elixir.UnsafeProcessSpawn do
  @moduledoc """
  Unsafe Process Spawning vulnerability pattern for Elixir applications.

  This pattern detects potentially dangerous process spawning that lacks proper
  supervision and error handling, which can lead to resource exhaustion and
  system instability.

  ## Vulnerability Details

  Unsafe process spawning occurs when:
  - Using `spawn/1` or `spawn/3` instead of `spawn_link/1` or supervised alternatives
  - Creating unsupervised processes that can crash without recovery
  - Spawning processes for critical operations without error handling
  - Using `Task.start/1` instead of `Task.start_link/1` for important work
  - Creating processes that can leak resources when they crash

  ## Technical Impact

  Resource exhaustion and system instability through:
  - Unlinked processes that crash silently without notification
  - Resource leaks from crashed processes with no cleanup
  - Potential for unbounded process creation leading to system exhaustion
  - Loss of fault tolerance and error recovery capabilities
  - Orphaned processes that consume memory and CPU resources

  ## Examples

  Vulnerable patterns:
  ```elixir
  # VULNERABLE - unlinked process can crash silently
  spawn(fn -> process_user_data(untrusted_input) end)

  # VULNERABLE - no supervision for critical work
  spawn(UserModule, :handle_request, [request])

  # VULNERABLE - Task.start creates unsupervised process
  Task.start(fn -> expensive_computation() end)

  # VULNERABLE - remote spawn without linking
  Node.spawn(remote_node, fn -> critical_work() end)
  ```

  Safe alternatives:
  ```elixir
  # SAFE - linked process will propagate failures
  spawn_link(fn -> process_user_data(untrusted_input) end)

  # SAFE - supervised task with proper error handling
  Task.start_link(fn -> process_user_data(untrusted_input) end)

  # SAFE - supervised by Task.Supervisor
  Task.Supervisor.start_child(MySupervisor, fn -> work() end)

  # SAFE - proper GenServer with supervision
  GenServer.start_link(MyWorker, initial_state)
  ```

  ## Attack Scenarios

  1. **Resource Exhaustion**: Attacker triggers creation of many unsupervised
     processes that consume system resources without cleanup

  2. **System Instability**: Critical processes crash without supervision,
     causing degraded functionality or complete service failure

  3. **Memory Leaks**: Crashed processes leave behind leaked memory and
     file descriptors that gradually exhaust system resources

  4. **Silent Failures**: Important operations fail without proper error
     handling or recovery mechanisms

  ## References

  - Elixir Process Documentation: https://hexdocs.pm/elixir/processes.html
  - OTP Supervision Principles: https://www.erlang.org/doc/design_principles/sup_princ.html
  - CloudBees Supervision Guide: https://www.cloudbees.com/blog/linking-monitoring-and-supervising-in-elixir
  - CWE-400: Uncontrolled Resource Consumption
  - OWASP Top 10 2021 - A05: Security Misconfiguration
  """

  use Rsolv.Security.Patterns.PatternBase

  @impl true
  def pattern do
    %Rsolv.Security.Pattern{
      id: "elixir-unsafe-process-spawn",
      name: "Unsafe Process Spawning",
      description:
        "Unsafe process spawning without proper supervision that can lead to resource exhaustion and system instability",
      type: :resource_exhaustion,
      severity: :medium,
      languages: ["elixir"],
      frameworks: [],
      regex: [
        # Basic spawn patterns without linking
        ~r/\bspawn\s*\(\s*fn\s*->/,
        ~r/\bspawn\s+fn\s*->/,
        ~r/\bspawn\s*\(\s*[A-Z]\w*\s*,\s*:\w+\s*,/,

        # Process.spawn patterns
        ~r/Process\.spawn\s*\(/,

        # Node.spawn patterns (remote spawning)
        ~r/Node\.spawn\s*\(/,

        # Task.start patterns (unsupervised)
        ~r/Task\.start\s*\(/,
        ~r/Task\.async\s*\(/,

        # General spawn patterns with dangerous operations
        ~r/spawn\s*\([^)]*(?:System\.shell|File\.write|:os\.cmd|Code\.eval)/,
        ~r/spawn\s+fn[^)]*(?:System\.shell|File\.write|:os\.cmd|Code\.eval)/,

        # Spawn with user input or external data
        ~r/spawn\s*\([^)]*(?:user_|input|params|request|data)/i,
        ~r/spawn\s+fn[^)]*(?:user_|input|params|request|data)/i
      ],
      cwe_id: "CWE-400",
      owasp_category: "A05:2021",
      recommendation:
        "Use spawn_link/1, Task.start_link/1, or proper supervision trees instead of unlinked spawn calls",
      test_cases: %{
        vulnerable: [
          ~S|spawn(fn -> execute_user_code(input) end)|,
          ~S|spawn(MyModule, :process_data, [user_input])|,
          ~S|Task.start(fn -> process_data(input) end)|,
          ~S|Node.spawn(node, fn -> remote_work() end)|
        ],
        safe: [
          ~S|spawn_link(fn -> work() end)|,
          ~S|Task.start_link(fn -> work() end)|,
          ~S|GenServer.start_link(MyServer, [])|,
          ~S|Task.Supervisor.start_child(sup, fn -> work() end)|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      attack_vectors: """
      1. Resource exhaustion: Attacker triggers creation of many unsupervised processes
      2. System Instability: Critical processes crash without supervision or recovery
      3. Memory Leaks: Crashed processes leave behind leaked resources
      4. Silent Failures: Important operations fail without proper error handling
      """,
      business_impact: """
      High: System instability can lead to:
      - Service outages from resource exhaustion
      - Data loss from unhandled process crashes
      - Degraded performance from resource leaks
      - Increased operational costs from system instability
      """,
      technical_impact: """
      Medium: Unsafe process spawning can cause:
      - Uncontrolled resource consumption (memory, CPU, file descriptors)
      - Silent process failures without error reporting
      - System instability from orphaned processes
      - Loss of fault tolerance and error recovery
      """,
      likelihood: "Medium: Common in applications that don't follow OTP supervision principles",
      cve_examples: [
        "CWE-400: Uncontrolled Resource Consumption",
        "CWE-459: Incomplete Cleanup",
        "CWE-771: Missing Reference to Active Allocated Resource"
      ],
      compliance_standards: [
        "OWASP Top 10 2021 - A05: Security Misconfiguration",
        "NIST Cybersecurity Framework - ID.AM: Asset Management",
        "ISO 27001 - A.12.1: Operational Procedures and Responsibilities"
      ],
      remediation_steps: """
      1. Replace spawn/1 with spawn_link/1 for linked processes
      2. Use Task.start_link/1 instead of Task.start/1
      3. Implement proper supervision trees for critical processes
      4. Use Task.Supervisor for managing task processes
      5. Consider GenServer for stateful process management
      6. Implement proper error handling and recovery mechanisms
      """,
      prevention_tips: """
      1. Follow OTP supervision principles for all process creation
      2. Use linked processes (spawn_link, Task.start_link) by default
      3. Implement proper supervision trees with restart strategies
      4. Monitor process resource usage and implement limits
      5. Use try-catch blocks for error handling in spawned processes
      6. Regularly audit process creation patterns in code reviews
      """,
      detection_methods: """
      1. Static code analysis for unlinked spawn patterns
      2. Runtime monitoring of process creation and lifecycle
      3. Resource usage monitoring for leaked processes
      4. Process tree analysis for unsupervised processes
      5. Code review focusing on process spawning patterns
      """,
      safe_alternatives: """
      1. Use spawn_link/1 instead of spawn/1 for linked processes
      2. Use Task.start_link/1 instead of Task.start/1
      3. Implement Task.Supervisor for supervised task management
      4. Use GenServer with proper supervision for stateful processes
      5. Design proper supervision trees with restart strategies
      6. Use Process.monitor/1 for explicit process monitoring
      """
    }
  end

  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.7,
      context_rules: %{
        exclude_test_files: true,
        test_file_patterns: [
          ~r/_test\.exs$/,
          ~r/\/test\//,
          ~r/test_helper\.exs$/
        ],
        supervision_indicators: [
          "Supervisor",
          "DynamicSupervisor",
          "Task.Supervisor",
          "GenServer",
          "start_link"
        ],
        check_supervision_context: true,
        dangerous_operations: [
          "System.shell",
          "File.write",
          ":os.cmd",
          "Code.eval",
          "user_input",
          "params",
          "request"
        ]
      },
      confidence_rules: %{
        base: 0.7,
        adjustments: %{
          supervision_context_bonus: -0.3,
          test_context_penalty: -0.5,
          dangerous_operation_bonus: 0.2,
          user_input_bonus: 0.1
        }
      },
      ast_rules: %{
        node_type: "process_analysis",
        process_analysis: %{
          check_spawn_calls: true,
          check_task_calls: true,
          spawn_functions: ["spawn", "Process.spawn", "Node.spawn"],
          task_functions: ["Task.start", "Task.async"]
        },
        supervision_analysis: %{
          check_supervision_tree: true,
          check_linked_processes: true,
          supervised_patterns: ["spawn_link", "Task.start_link", "GenServer.start_link"],
          supervision_keywords: ["Supervisor", "start_link", "DynamicSupervisor"]
        },
        context_analysis: %{
          check_dangerous_operations: true,
          check_user_input: true,
          dangerous_functions: ["System.shell", "File.write", ":os.cmd", "Code.eval"],
          user_input_indicators: ["user_", "input", "params", "request", "data"]
        }
      }
    }
  end
end
