defmodule RsolvApi.Security.Patterns.Java.CommandInjectionProcessbuilderTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Java.CommandInjectionProcessbuilder
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = CommandInjectionProcessbuilder.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "java-command-injection-processbuilder"
      assert pattern.name == "Command Injection via ProcessBuilder"
      assert pattern.severity == :high
      assert pattern.type == :command_injection
      assert pattern.languages == ["java"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = CommandInjectionProcessbuilder.pattern()
      
      assert pattern.cwe_id == "CWE-78"
      assert pattern.owasp_category == "A03:2021"
    end
    
    test "has regex patterns" do
      pattern = CommandInjectionProcessbuilder.pattern()
      
      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 4
      assert Enum.all?(pattern.regex, &is_struct(&1, Regex))
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = CommandInjectionProcessbuilder.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches ProcessBuilder.command with string concatenation", %{pattern: pattern} do
      vulnerable_code = [
        "ProcessBuilder pb = new ProcessBuilder();\npb.command(\"sh\", \"-c\", userCommand);",
        "ProcessBuilder pb = new ProcessBuilder();\npb.command(\"cmd\", \"/c\", command + args);",
        "new ProcessBuilder().command(\"bash\", \"-c\", script + userInput);",
        "pb.command(\"/bin/sh\", \"-c\", \"echo \" + userInput);"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "matches ProcessBuilder with shell invocation and concatenation", %{pattern: pattern} do
      vulnerable_code = [
        "ProcessBuilder pb = new ProcessBuilder(\"sh\", \"-c\", cmd + args);",
        "new ProcessBuilder(\"cmd\", \"/c\", \"dir \" + directory);",
        "ProcessBuilder builder = new ProcessBuilder(\"/bin/bash\", \"-c\", command);",
        "ProcessBuilder proc = new ProcessBuilder(\"powershell\", \"-Command\", script);"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "matches ProcessBuilder with List construction", %{pattern: pattern} do
      vulnerable_code = [
        "List<String> command = Arrays.asList(\"sh\", \"-c\", userInput);\nProcessBuilder pb = new ProcessBuilder(command);",
        "List<String> cmd = new ArrayList<>();\ncmd.add(\"bash\");\ncmd.add(\"-c\");\ncmd.add(userCommand);\nProcessBuilder pb = new ProcessBuilder(cmd);"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe ProcessBuilder usage", %{pattern: pattern} do
      safe_code = [
        "ProcessBuilder pb = new ProcessBuilder(\"echo\", \"Hello World\");",
        "ProcessBuilder pb = new ProcessBuilder(\"ls\", \"-la\");",
        "// Comment about ProcessBuilder\n// ProcessBuilder pb = new ProcessBuilder(\"sh\", \"-c\", userInput);",
        "String info = \"Using ProcessBuilder for safe command execution\";",
        "ProcessBuilder pb = new ProcessBuilder(\"git\", \"status\");\npb.directory(new File(\"/home/user/project\"));"
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should not match: #{code}"
      end
    end
    
    test "matches shell metacharacter patterns", %{pattern: pattern} do
      vulnerable_code = [
        "pb.command(\"sh\", \"-c\", \"cat \" + file + \" | grep \" + searchPattern);",
        "new ProcessBuilder(\"bash\", \"-c\", \"echo \" + data + \" > \" + outputFile);",
        "ProcessBuilder p = new ProcessBuilder(\"cmd\", \"/c\", \"type \" + file + \" && \" + command);"
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = CommandInjectionProcessbuilder.vulnerability_metadata()
      
      assert String.contains?(String.downcase(metadata.description), "command injection")
      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 5
      assert length(metadata.real_world_impact) >= 4
      assert length(metadata.cve_examples) >= 2
    end
    
    test "includes ProcessBuilder-specific information" do
      metadata = CommandInjectionProcessbuilder.vulnerability_metadata()
      
      assert String.contains?(metadata.description, "ProcessBuilder")
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "ProcessBuilder"))
    end
    
    test "includes proper security references" do
      metadata = CommandInjectionProcessbuilder.vulnerability_metadata()
      
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
    
    test "includes shell-specific attack vectors" do
      metadata = CommandInjectionProcessbuilder.vulnerability_metadata()
      
      assert Enum.any?(metadata.attack_vectors, &String.contains?(&1, "Shell"))
      assert Enum.any?(metadata.attack_vectors, &String.contains?(&1, "-c"))
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = CommandInjectionProcessbuilder.ast_enhancement()
      
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.7
    end
    
    test "includes ProcessBuilder method analysis" do
      enhancement = CommandInjectionProcessbuilder.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "MethodInvocation"
      assert enhancement.ast_rules.processbuilder_analysis.check_method_name
      assert enhancement.ast_rules.processbuilder_analysis.builder_methods
      assert enhancement.ast_rules.processbuilder_analysis.check_shell_invocation
    end
    
    test "has shell detection rules" do
      enhancement = CommandInjectionProcessbuilder.ast_enhancement()
      
      assert enhancement.ast_rules.shell_detection.check_shell_programs
      assert enhancement.ast_rules.shell_detection.shell_programs
      assert enhancement.ast_rules.shell_detection.shell_flags
    end
    
    test "includes safe pattern detection" do
      enhancement = CommandInjectionProcessbuilder.ast_enhancement()
      
      assert enhancement.context_rules.check_static_commands
      assert enhancement.context_rules.safe_patterns
      assert enhancement.context_rules.check_user_input
    end
  end
end