defmodule Rsolv.Security.Patterns.Python.CommandInjectionSubprocessShellTest do
  use ExUnit.Case
  alias Rsolv.Security.Patterns.Python.CommandInjectionSubprocessShell
  alias Rsolv.Security.Pattern

  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = CommandInjectionSubprocessShell.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "python-command-injection-subprocess-shell"
      assert pattern.name == "Command Injection via subprocess with shell=True"
      assert pattern.type == :command_injection
      assert pattern.severity == :critical
      assert pattern.languages == ["python"]
      assert pattern.cwe_id == "CWE-78"
      assert pattern.owasp_category == "A03:2021"
    end
  end

  describe "vulnerability detection" do
    setup do
      {:ok, pattern: CommandInjectionSubprocessShell.pattern()}
    end

    test "detects subprocess.run with shell=True", %{pattern: pattern} do
      vulnerable_code = [
        ~S|subprocess.run(cmd, shell=True)|,
        ~S|subprocess.run("ls " + user_input, shell=True)|,
        ~S|subprocess.run(f"ping {host}", shell=True)|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code), 
               "Should match vulnerable code: #{code}"
      end
    end

    test "detects subprocess.call with shell=True", %{pattern: pattern} do
      assert Regex.match?(pattern.regex, ~S|subprocess.call(cmd, shell=True)|)
      assert Regex.match?(pattern.regex, ~S|subprocess.call("echo " + user_input, shell=True)|)
    end

    test "detects subprocess.Popen with shell=True", %{pattern: pattern} do
      assert Regex.match?(pattern.regex, ~S|subprocess.Popen(cmd, shell=True)|)
      assert Regex.match?(pattern.regex, ~S|subprocess.Popen(f"tail -f {logfile}", shell=True)|)
    end

    test "ignores safe subprocess usage", %{pattern: pattern} do
      safe_code = [
        ~S|subprocess.run(["ls", "-la"])|,
        ~S|subprocess.run(["echo", message], shell=False)|,
        ~S|subprocess.call(["ping", "-c", "4", host])|
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code), 
               "Should NOT match safe code: #{code}"
      end
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive vulnerability metadata" do
      metadata = CommandInjectionSubprocessShell.vulnerability_metadata()
      
      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert is_list(metadata.references)
      assert length(metadata.references) > 0
      assert is_list(metadata.attack_vectors)
      assert length(metadata.attack_vectors) > 0
      assert is_list(metadata.real_world_impact)
      assert is_list(metadata.cve_examples)
      assert is_binary(metadata.detection_notes)
      assert is_list(metadata.safe_alternatives)
    end
  end

  describe "ast_enhancement/0" do
    test "returns AST enhancement rules" do
      enhancement = CommandInjectionSubprocessShell.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
    end

    test "confidence scoring reduces false positives" do
      enhancement = CommandInjectionSubprocessShell.ast_enhancement()
      
      assert enhancement.min_confidence == 0.8
      assert enhancement.confidence_rules.base == 0.5
      assert enhancement.confidence_rules.adjustments["has_shell_true"] == 0.4
      assert enhancement.confidence_rules.adjustments["in_test_code"] == -1.0
    end
  end

  describe "enhanced_pattern/0" do
    test "uses AST enhancement" do
      enhanced = CommandInjectionSubprocessShell.enhanced_pattern()
      
      assert enhanced.id == "python-command-injection-subprocess-shell"
      assert enhanced.ast_rules
      assert enhanced.min_confidence == 0.8
    end
  end

  describe "applies_to_file?/1" do
    test "applies to Python files" do
      assert CommandInjectionSubprocessShell.applies_to_file?("script.py", nil)
      assert CommandInjectionSubprocessShell.applies_to_file?("utils/helper.py", nil)
      assert CommandInjectionSubprocessShell.applies_to_file?("src/main.py", nil)
      
      refute CommandInjectionSubprocessShell.applies_to_file?("script.js", nil)
      refute CommandInjectionSubprocessShell.applies_to_file?("config.rb", nil)
      refute CommandInjectionSubprocessShell.applies_to_file?("README.md", nil)
    end
  end
end