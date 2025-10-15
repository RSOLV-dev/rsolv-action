defmodule Rsolv.Security.Patterns.Elixir.CommandInjectionSystemTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Elixir.CommandInjectionSystem
  alias Rsolv.Security.Pattern

  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = CommandInjectionSystem.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "elixir-command-injection-system"
      assert pattern.name == "OS Command Injection in Elixir"
      assert pattern.severity == :critical
      assert pattern.type == :command_injection
      assert pattern.languages == ["elixir"]
      assert pattern.cwe_id == "CWE-78"
      assert pattern.owasp_category == "A03:2021"
      assert is_struct(pattern.regex, Regex) or is_list(pattern.regex)
    end

    test "includes comprehensive test cases" do
      pattern = CommandInjectionSystem.pattern()

      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
      assert is_list(pattern.test_cases.vulnerable)
      assert is_list(pattern.test_cases.safe)
      assert length(pattern.test_cases.vulnerable) >= 2
      assert length(pattern.test_cases.safe) >= 2
    end

    test "has appropriate recommendation" do
      pattern = CommandInjectionSystem.pattern()

      assert String.contains?(String.downcase(pattern.recommendation), "system.cmd") or
               String.contains?(String.downcase(pattern.recommendation), "arguments")

      assert String.contains?(String.downcase(pattern.recommendation), "interpolation") or
               String.contains?(String.downcase(pattern.recommendation), "sanitiz")
    end
  end

  describe "regex matching" do
    test "detects System.shell with string interpolation" do
      pattern = CommandInjectionSystem.pattern()

      vulnerable_code = [
        ~S|System.shell("rm -rf #{path}")|,
        ~S|System.shell("ls #{directory}")|,
        ~S|System.shell("cat #{file_name}")|,
        ~S|System.shell("grep #{pattern} #{file}")|,
        ~S|System.shell("find #{search_path} -name #{name}")|
      ]

      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]

        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end

    test "detects :os.cmd with string interpolation" do
      pattern = CommandInjectionSystem.pattern()

      vulnerable_code = [
        ~S|:os.cmd('rm -rf #{path}')|,
        ~S|:os.cmd('ls #{directory}')|,
        ~S|:os.cmd('whoami #{user}')|,
        ~S|:os.cmd('ping #{host}')|,
        ~S|:os.cmd('tar -xf #{archive}')|
      ]

      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]

        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end

    test "detects System.shell with concatenation" do
      pattern = CommandInjectionSystem.pattern()

      vulnerable_code = [
        ~S|System.shell("rm -rf " <> path)|,
        ~S|System.shell("ls " <> directory)|,
        ~S|System.shell(command <> " " <> args)|,
        ~S|System.shell(base_cmd <> " --input " <> input_file)|,
        ~S|System.shell("echo " <> message <> " > " <> output_file)|
      ]

      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]

        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end

    test "detects :os.cmd with concatenation" do
      pattern = CommandInjectionSystem.pattern()

      vulnerable_code = [
        ~S|:os.cmd('ls ' ++ directory)|,
        ~S|:os.cmd('grep ' ++ pattern ++ ' file.txt')|,
        ~S|:os.cmd(command ++ ' ' ++ args)|,
        ~S|:os.cmd('find ' ++ path ++ ' -type f')|,
        ~S|:os.cmd('curl ' ++ url)|
      ]

      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]

        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end

    test "detects System.shell with dynamic command construction" do
      pattern = CommandInjectionSystem.pattern()

      vulnerable_code = [
        ~S|System.shell(Enum.join(["ls", path], " "))|,
        ~S|System.shell("#{base_command} #{user_input}")|,
        ~S|System.shell(build_command(user_params))|,
        ~S|System.shell("docker run #{image} #{command}")|,
        ~S|System.shell("ssh #{user}@#{host} '#{remote_cmd}'")|
      ]

      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]

        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end

    test "detects Port.open with dynamic commands" do
      pattern = CommandInjectionSystem.pattern()

      vulnerable_code = [
        ~S|Port.open({:spawn, "ls #{directory}"})|,
        ~S|Port.open({:spawn_executable, "/bin/bash"}, [:binary, args: ["-c", "rm #{file}"]])|,
        ~S|Port.open({:spawn, command <> " " <> args})|,
        ~S|Port.open({:spawn, "curl #{url}"})|,
        ~S|Port.open({:spawn_executable, exe_path}, [:binary, args: ["--input", user_input]])|
      ]

      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]

        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end

    test "does not match safe command execution" do
      pattern = CommandInjectionSystem.pattern()

      safe_code = [
        ~S|System.cmd("ls", [directory])|,
        ~S|System.cmd("rm", ["-rf", path])|,
        ~S|System.shell("echo 'Hello World'")|,
        ~S|:os.cmd('whoami')|,
        ~S|// System.shell("rm #{file}") in comment|,
        ~S|"This is just a string with System.shell in it"|,
        ~S|Logger.info("Running command: System.shell"))|,
        ~S|Port.open({:spawn_executable, "/bin/ls"}, [:binary, args: ["-la"]])|
      ]

      for code <- safe_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]

        refute Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should not match: #{code}"
      end
    end

    test "detects command injection in shell scripts" do
      pattern = CommandInjectionSystem.pattern()

      vulnerable_code = [
        ~S|System.shell("bash -c 'ls #{directory}'")|,
        ~S|System.shell("sh -c 'find #{path} -name *.txt'")|,
        ~S|:os.cmd('bash -c "grep #{pattern} file.txt"')|,
        ~S|System.shell("zsh -c 'cd #{dir} && ls'")|,
        ~S|:os.cmd('perl -e "print #{user_input}"')|
      ]

      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]

        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end

    test "detects command injection with network commands" do
      pattern = CommandInjectionSystem.pattern()

      vulnerable_code = [
        ~S|System.shell("curl #{url}")|,
        ~S|System.shell("wget #{download_url}")|,
        ~S|:os.cmd('ping -c 1 #{host}')|,
        ~S|System.shell("nslookup #{domain}")|,
        ~S|:os.cmd('netcat #{target_host} #{port}')|
      ]

      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]

        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = CommandInjectionSystem.vulnerability_metadata()

      assert String.contains?(String.downcase(metadata.description), "command") and
               String.contains?(String.downcase(metadata.description), "injection")

      assert String.contains?(String.downcase(metadata.description), "system") or
               String.contains?(String.downcase(metadata.description), "shell")

      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 4
      assert length(metadata.real_world_impact) >= 4
      assert length(metadata.cve_examples) >= 2
    end

    test "includes Elixir specific information" do
      metadata = CommandInjectionSystem.vulnerability_metadata()

      assert String.contains?(metadata.description, "System.shell") or
               String.contains?(metadata.description, ":os.cmd")

      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "System.cmd")) or
               Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "arguments"))

      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "validation")) or
               Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "sanitiz"))
    end

    test "includes proper security references" do
      metadata = CommandInjectionSystem.vulnerability_metadata()

      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end

    test "includes command injection specific attack information" do
      metadata = CommandInjectionSystem.vulnerability_metadata()

      assert Enum.any?(metadata.additional_context.secure_patterns, fn pattern ->
               String.contains?(String.downcase(pattern), "system.cmd") or
                 String.contains?(String.downcase(pattern), "arguments") or
                 String.contains?(String.downcase(pattern), "validation")
             end)
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = CommandInjectionSystem.ast_enhancement()

      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)

      assert enhancement.min_confidence >= 0.7
    end

    test "includes command execution analysis" do
      enhancement = CommandInjectionSystem.ast_enhancement()

      assert enhancement.ast_rules.node_type == "CallExpression" or
               enhancement.ast_rules.node_type == "FunctionCall"

      assert enhancement.ast_rules.command_analysis.check_command_execution
      assert enhancement.ast_rules.command_analysis.dangerous_functions
      assert enhancement.ast_rules.command_analysis.unsafe_patterns
    end

    test "has string construction detection rules" do
      enhancement = CommandInjectionSystem.ast_enhancement()

      assert enhancement.ast_rules.string_analysis.check_dynamic_construction
      assert enhancement.ast_rules.string_analysis.interpolation_patterns
      assert enhancement.ast_rules.string_analysis.concatenation_patterns
    end

    test "includes input validation analysis" do
      enhancement = CommandInjectionSystem.ast_enhancement()

      assert enhancement.ast_rules.input_analysis.check_user_input
      assert enhancement.ast_rules.input_analysis.dangerous_input_sources
      assert enhancement.ast_rules.input_analysis.safe_input_patterns
    end

    test "includes context-based filtering" do
      enhancement = CommandInjectionSystem.ast_enhancement()

      assert enhancement.context_rules.check_command_context
      assert enhancement.context_rules.safe_command_patterns
      assert enhancement.context_rules.unsafe_command_indicators
    end

    test "has proper confidence scoring" do
      enhancement = CommandInjectionSystem.ast_enhancement()

      adjustments = enhancement.confidence_rules.adjustments
      assert Map.has_key?(adjustments, "has_input_validation")
      assert Map.has_key?(adjustments, "dynamic_command_construction")
      assert Map.has_key?(adjustments, "in_test_code")
      assert Map.has_key?(adjustments, "known_safe_function")
    end
  end
end
