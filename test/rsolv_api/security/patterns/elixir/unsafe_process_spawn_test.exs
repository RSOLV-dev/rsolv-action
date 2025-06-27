defmodule RsolvApi.Security.Patterns.Elixir.UnsafeProcessSpawnTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Elixir.UnsafeProcessSpawn
  alias RsolvApi.Security.Pattern

  describe "unsafe_process_spawn pattern" do
    test "returns correct pattern structure" do
      pattern = UnsafeProcessSpawn.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "elixir-unsafe-process-spawn"
      assert pattern.name == "Unsafe Process Spawning"
      assert pattern.type == :resource_exhaustion
      assert pattern.severity == :medium
      assert pattern.languages == ["elixir"]
      assert pattern.frameworks == []
      assert pattern.cwe_id == "CWE-400"
      assert pattern.owasp_category == "A05:2021"
      
      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects basic spawn calls with user code" do
      pattern = UnsafeProcessSpawn.pattern()
      
      test_cases = [
        "spawn(fn -> execute_user_code(input) end)",
        "spawn fn -> process_user_data(data) end",
        "spawn(MyModule, :process_data, [user_input])",
        "spawn(UserModule, function, params)"
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects spawn with dangerous operations" do
      pattern = UnsafeProcessSpawn.pattern()
      
      test_cases = [
        "spawn(fn -> System.shell(user_command) end)",
        "spawn fn -> File.write!(user_path, data) end",
        "spawn(fn -> :os.cmd(user_input) end)",
        "spawn(fn -> Code.eval_string(user_code) end)"
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects unlinked process spawning patterns" do
      pattern = UnsafeProcessSpawn.pattern()
      
      test_cases = [
        "spawn(Module, :function, args)",
        "Process.spawn(fn -> work() end, [])",
        "Node.spawn(node, fn -> remote_work() end)",
        "Node.spawn(node, Module, :function, args)"
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects spawn without supervision" do
      pattern = UnsafeProcessSpawn.pattern()
      
      test_cases = [
        "spawn(fn ->\n  loop_forever()\nend)",
        "spawn(fn -> handle_request(req) end)",
        "spawn(UserHandler, :handle, [request])"
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects unsupervised Task.start patterns" do
      pattern = UnsafeProcessSpawn.pattern()
      
      test_cases = [
        "Task.start(fn -> process_data(input) end)",
        "Task.start(Module, :function, [args])",
        "Task.async(fn -> unsafe_operation() end)"
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "does not detect safe supervised patterns" do
      pattern = UnsafeProcessSpawn.pattern()
      
      safe_code = [
        "spawn_link(fn -> work() end)",
        "Task.start_link(fn -> work() end)",
        "Task.Supervisor.start_child(supervisor, fn -> work() end)",
        "GenServer.start_link(MyServer, [])",
        "DynamicSupervisor.start_child(sup, {Worker, args})",
        "Supervisor.start_child(sup, worker_spec)"
      ]
      
      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "does not detect safe spawn usage" do
      pattern = UnsafeProcessSpawn.pattern()
      
      safe_code = [
        "spawn_link(fn -> Logger.info(\"message\") end)",
        "spawn_monitor(fn -> safe_computation() end)",
        "# This is about spawn points in games",
        "config :game, spawn_rate: 100"
      ]
      
      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = UnsafeProcessSpawn.vulnerability_metadata()
      
      assert metadata.attack_vectors
      assert metadata.business_impact  
      assert metadata.technical_impact
      assert metadata.likelihood
      assert metadata.cve_examples
      assert metadata.compliance_standards
      assert metadata.remediation_steps
      assert metadata.prevention_tips
      assert metadata.detection_methods
      assert metadata.safe_alternatives
    end

    test "vulnerability metadata contains process-specific information" do
      metadata = UnsafeProcessSpawn.vulnerability_metadata()
      
      assert String.contains?(metadata.attack_vectors, "Resource exhaustion")
      assert String.contains?(metadata.business_impact, "system")
      assert String.contains?(metadata.technical_impact, "process")
      assert String.contains?(metadata.safe_alternatives, "spawn_link")
      assert String.contains?(metadata.prevention_tips, "supervision")
    end

    test "includes AST enhancement rules" do
      enhancement = UnsafeProcessSpawn.ast_enhancement()
      
      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has process-specific rules" do
      enhancement = UnsafeProcessSpawn.ast_enhancement()
      
      assert enhancement.context_rules.exclude_test_files
      assert enhancement.context_rules.supervision_indicators
      assert enhancement.ast_rules.process_analysis
      assert enhancement.ast_rules.supervision_analysis
      assert enhancement.confidence_rules.adjustments.supervision_context_bonus
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = UnsafeProcessSpawn.enhanced_pattern()
      
      assert enhanced.id == "elixir-unsafe-process-spawn"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = UnsafeProcessSpawn.pattern()
      
      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end
  end
end