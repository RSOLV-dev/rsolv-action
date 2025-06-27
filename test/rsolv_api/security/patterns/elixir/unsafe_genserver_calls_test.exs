defmodule RsolvApi.Security.Patterns.Elixir.UnsafeGenserverCallsTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Elixir.UnsafeGenserverCalls
  alias RsolvApi.Security.Pattern

  describe "unsafe_genserver_calls pattern" do
    test "returns correct pattern structure" do
      pattern = UnsafeGenserverCalls.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "elixir-unsafe-genserver-calls"
      assert pattern.name == "Unsafe GenServer Calls"
      assert pattern.type == :rce
      assert pattern.severity == :medium
      assert pattern.languages == ["elixir"]
      assert pattern.cwe_id == "CWE-94"
      assert pattern.owasp_category == "A03:2021"
      
      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects GenServer.call with execute command" do
      pattern = UnsafeGenserverCalls.pattern()
      
      test_cases = [
        ~S|GenServer.call(pid, {:execute, user_command})|,
        ~S|GenServer.call(server, {:execute, params["cmd"]})|,
        ~S|GenServer.call(MyServer, {:execute, input})|,
        ~S|GenServer.call(worker, {:execute, command_string})|,
        ~S|GenServer.call(process, {:execute, untrusted_data})|
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects GenServer.call with run or eval commands" do
      pattern = UnsafeGenserverCalls.pattern()
      
      test_cases = [
        ~S|GenServer.call(pid, {:run, user_code})|,
        ~S|GenServer.call(server, {:eval, params["code"]})|,
        ~S|GenServer.call(MyServer, {:run_code, input})|,
        ~S|GenServer.call(worker, {:eval_string, code})|,
        ~S|GenServer.call(process, {:run_command, cmd})|
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects GenServer.call with dynamic command interpolation" do
      pattern = UnsafeGenserverCalls.pattern()
      
      test_cases = [
        ~S|GenServer.call(pid, {:"#{cmd}", data})|,
        ~S|GenServer.call(server, {String.to_atom(cmd), args})|,
        ~S|GenServer.call(MyServer, {action, user_input})|,
        ~S|GenServer.call(worker, request)|,
        ~S|GenServer.call(process, untrusted_message)|
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects multi-line GenServer.call patterns" do
      pattern = UnsafeGenserverCalls.pattern()
      
      test_cases = [
        ~S"""
        GenServer.call(
          server,
          {:execute, command}
        )
        """,
        ~S"""
        GenServer.call(
          worker,
          {:run, user_code},
          5000
        )
        """,
        ~S"""
        request = {:execute, params["cmd"]}
        GenServer.call(pid, request)
        """
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects handle_call with execute pattern" do
      pattern = UnsafeGenserverCalls.pattern()
      
      test_cases = [
        ~S|def handle_call({:execute, cmd}, _from, state) do|,
        ~S|def handle_call({:run, code}, from, state) do|,
        ~S|def handle_call({:eval, expr}, _from, state) do|,
        ~S|def handle_call({:run_command, command}, _, state) do|,
        ~S|def handle_call({:execute_code, code}, _from, state) do|
      ]
      
      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "does not detect safe GenServer patterns" do
      pattern = UnsafeGenserverCalls.pattern()
      
      safe_code = [
        # Safe predefined commands
        ~S|GenServer.call(pid, :get_state)|,
        ~S|GenServer.call(server, {:increment, 1})|,
        ~S|GenServer.call(MyServer, {:update, validated_data})|,
        # Validated commands
        ~S"""
        case validate_command(user_command) do
          {:ok, safe_command} -> GenServer.call(pid, {:execute, safe_command})
          :error -> {:error, :invalid_command}
        end
        """,
        # Safe handle_call patterns
        ~S|def handle_call(:get_status, _from, state) do|,
        ~S|def handle_call({:set_value, value}, _from, state) when is_integer(value) do|,
        # Comments
        ~S|# GenServer.call(pid, {:execute, user_command})|
      ]
      
      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "does not detect comments or documentation" do
      pattern = UnsafeGenserverCalls.pattern()
      
      safe_code = [
        ~S|# GenServer.call(pid, {:execute, cmd})|,
        ~S|@doc "Never use GenServer.call(pid, {:execute, user_input})"|,
        ~S|# TODO: Fix GenServer.call(server, {:run, code})"|,
        ~S"""
        # Unsafe example:
        # GenServer.call(pid, {:execute, user_command})
        """
      ]
      
      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = UnsafeGenserverCalls.vulnerability_metadata()
      
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

    test "vulnerability metadata contains GenServer specific information" do
      metadata = UnsafeGenserverCalls.vulnerability_metadata()
      
      assert String.contains?(metadata.attack_vectors, "GenServer")
      assert String.contains?(metadata.business_impact, "execution")
      assert String.contains?(metadata.technical_impact, "process")
      assert String.contains?(metadata.safe_alternatives, "validate")
      assert String.contains?(metadata.prevention_tips, "whitelist")
    end

    test "includes AST enhancement rules" do
      enhancement = UnsafeGenserverCalls.ast_enhancement()
      
      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has GenServer specific rules" do
      enhancement = UnsafeGenserverCalls.ast_enhancement()
      
      assert enhancement.context_rules.unsafe_commands
      assert enhancement.context_rules.genserver_functions
      assert enhancement.ast_rules.genserver_analysis
      assert enhancement.confidence_rules.adjustments.validated_command_penalty
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = UnsafeGenserverCalls.enhanced_pattern()
      
      assert enhanced.id == "elixir-unsafe-genserver-calls"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = UnsafeGenserverCalls.pattern()
      
      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end
  end
end