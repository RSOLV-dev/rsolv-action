defmodule RsolvApi.Security.Patterns.Python.CommandInjectionOsSystemTest do
  use RsolvApi.DataCase
  alias RsolvApi.Security.Patterns.Python.CommandInjectionOsSystem
  alias RsolvApi.Security.Pattern
  
  # Helper functions for cleaner test code
  defp assert_vulnerable(pattern, code_samples) do
    for code <- code_samples do
      assert Regex.match?(pattern.regex, code), 
             "Should match vulnerable code: #{code}"
    end
  end

  defp assert_safe(pattern, code_samples) do
    for code <- code_samples do
      refute Regex.match?(pattern.regex, code), 
             "Should NOT match safe code: #{code}"
    end
  end

  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = CommandInjectionOsSystem.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "python-command-injection-os-system"
      assert pattern.name == "Command Injection via os.system"
      assert pattern.type == :command_injection
      assert pattern.severity == :critical
      assert pattern.languages == ["python"]
      assert pattern.cwe_id == "CWE-78"
      assert pattern.owasp_category == "A03:2021"
    end
  end

  describe "vulnerability detection" do
    setup do
      {:ok, pattern: CommandInjectionOsSystem.pattern()}
    end

    test "detects os.system with string concatenation", %{pattern: pattern} do
      assert_vulnerable(pattern, [
        ~S|os.system("ls " + user_input)|,
        ~S|os.system("ping " + host)|,
        ~S|os.system("cat /tmp/" + filename)|,
        ~S|os.system('echo ' + message)|,
        ~S|os.system("rm -rf " + directory)|
      ])
    end

    test "detects os.system with f-string formatting", %{pattern: pattern} do
      assert_vulnerable(pattern, [
        ~S|os.system(f"ping {host}")|,
        ~S|os.system(f"cat {file_path}")|,
        ~S|os.system(f'echo {user_message}')|,
        ~S|os.system(f"ls -la {directory}")|,
        ~S|os.system(f'''tar -xvf {archive}''')|
      ])
    end

    test "detects os.system with % formatting", %{pattern: pattern} do
      assert_vulnerable(pattern, [
        ~S|os.system("ping %s" % host)|,
        ~S|os.system("echo %s" % (message,))|,
        ~S|os.system('ls %s' % directory)|,
        ~S|os.system("cat %s" % filename)|
      ])
    end

    test "detects os.system with .format()", %{pattern: pattern} do
      assert_vulnerable(pattern, [
        ~S|os.system("ping {}".format(host))|,
        ~S|os.system("echo {}".format(message))|,
        ~S|os.system('ls {}'.format(directory))|,
        ~S|os.system("cat {0}".format(filename))|
      ])
    end

    test "detects os.system with variable assignment", %{pattern: pattern} do
      assert_vulnerable(pattern, [
        ~S|cmd = "ping " + target; os.system(cmd)|,
        ~S|command = f"ls {path}"; os.system(command)|,
        ~S|exec_str = "echo %s" % msg; os.system(exec_str)|
      ])
    end

    test "ignores safe subprocess usage", %{pattern: pattern} do
      assert_safe(pattern, [
        ~S|subprocess.run(["ls", user_input], shell=False)|,
        ~S|subprocess.call(["ping", "-c", "4", host])|,
        ~S|subprocess.Popen(["cat", filename])|,
        ~S|subprocess.check_output(["echo", message])|
      ])
    end

    test "ignores non-command string operations", %{pattern: pattern} do
      assert_safe(pattern, [
        ~S|print("User: " + username)|,
        ~S|logger.info(f"Processing {filename}")|,
        ~S|message = "Hello %s" % name|,
        ~S|url = "https://api.example.com/{}".format(endpoint)|
      ])
    end

    test "ignores os.system with hardcoded commands", %{pattern: pattern} do
      assert_safe(pattern, [
        ~S|os.system("ls -la")|,
        ~S|os.system('clear')|,
        ~S|os.system("git status")|
      ])
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive vulnerability metadata" do
      metadata = CommandInjectionOsSystem.vulnerability_metadata()
      
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

    test "includes relevant CWE and OWASP references" do
      metadata = CommandInjectionOsSystem.vulnerability_metadata()
      
      cwe_ref = Enum.find(metadata.references, &(&1.type == :cwe))
      assert cwe_ref
      assert cwe_ref.id == "CWE-78"
      
      owasp_ref = Enum.find(metadata.references, &(&1.type == :owasp))
      assert owasp_ref
      assert owasp_ref.id == "A03:2021"
    end
  end

  describe "ast_enhancement/0" do
    test "returns AST enhancement rules" do
      enhancement = CommandInjectionOsSystem.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
    end

    test "AST rules target appropriate node types" do
      enhancement = CommandInjectionOsSystem.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "Call"
      assert enhancement.ast_rules.module == "os"
      assert enhancement.ast_rules.function == "system"
      assert is_map(enhancement.ast_rules.argument_analysis)
    end

    test "includes command injection context detection" do
      enhancement = CommandInjectionOsSystem.ast_enhancement()
      
      assert enhancement.context_rules.dangerous_patterns
      assert enhancement.context_rules.exclude_if_literal == true
      assert enhancement.context_rules.check_input_validation == true
    end

    test "confidence scoring reduces false positives" do
      enhancement = CommandInjectionOsSystem.ast_enhancement()
      
      assert enhancement.min_confidence == 0.8
      assert enhancement.confidence_rules.base == 0.6
      assert enhancement.confidence_rules.adjustments["has_user_input"] == 0.3
      assert enhancement.confidence_rules.adjustments["in_test_code"] == -1.0
    end
  end

  describe "enhanced_pattern/0" do
    test "uses AST enhancement" do
      enhanced = CommandInjectionOsSystem.enhanced_pattern()
      
      assert enhanced.id == "python-command-injection-os-system"
      assert enhanced.ast_rules
      assert enhanced.min_confidence == 0.8
    end
  end

  describe "applies_to_file?/1" do
    test "applies to Python files" do
      assert CommandInjectionOsSystem.applies_to_file?("script.py")
      assert CommandInjectionOsSystem.applies_to_file?("utils/helper.py")
      assert CommandInjectionOsSystem.applies_to_file?("src/main.py")
      
      refute CommandInjectionOsSystem.applies_to_file?("script.js")
      refute CommandInjectionOsSystem.applies_to_file?("config.rb")
      refute CommandInjectionOsSystem.applies_to_file?("README.md")
    end
  end
end