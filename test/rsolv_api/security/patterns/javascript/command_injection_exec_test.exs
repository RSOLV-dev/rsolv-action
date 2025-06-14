defmodule RsolvApi.Security.Patterns.Javascript.CommandInjectionExecTest do
  use ExUnit.Case, async: true
  doctest RsolvApi.Security.Patterns.Javascript.CommandInjectionExec
  
  alias RsolvApi.Security.Patterns.Javascript.CommandInjectionExec
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = CommandInjectionExec.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-command-injection-exec"
      assert pattern.name == "Command Injection via exec"
      assert pattern.type == :command_injection
      assert pattern.severity == :critical
      assert pattern.languages == ["javascript", "typescript"]
    end
    
    test "pattern detects vulnerable exec calls with concatenation" do
      pattern = CommandInjectionExec.pattern()
      
      vulnerable_cases = [
        ~S|exec("ls " + userInput)|,
        ~S|execSync("cat /tmp/" + req.params.file)|,
        ~S|child_process.exec("rm -rf " + directory)|,
        ~S|exec('echo ' + userData + ' > output.txt')|,
        ~S|require('child_process').exec("curl " + url)|
      ]
      
      for code <- vulnerable_cases do
        assert Regex.match?(pattern.regex, code), 
          "Failed to match vulnerable code: #{code}"
      end
    end
    
    test "pattern detects vulnerable exec calls with template literals" do
      pattern = CommandInjectionExec.pattern()
      
      vulnerable_cases = [
        ~S|exec(`git clone ${repoUrl}`)|,
        ~S|execSync(`rm -rf /tmp/${dirname}`)|,
        "exec(`echo ${message} | mail admin@example.com`)",
        ~S|child_process.exec(`docker run ${imageName}`)|
      ]
      
      for code <- vulnerable_cases do
        assert Regex.match?(pattern.regex, code), 
          "Failed to match vulnerable code: #{code}"
      end
    end
    
    test "pattern does not match safe exec usage" do
      pattern = CommandInjectionExec.pattern()
      
      safe_cases = [
        ~S|execFile("ls", [userInput])|,
        ~S|spawn("git", ["clone", repoUrl])|,
        ~S|exec("ls -la")|,  # No user input
        ~S|execFile("cat", ["/tmp/safe.txt"])|
      ]
      
      for code <- safe_cases do
        refute Regex.match?(pattern.regex, code), 
          "Incorrectly matched safe code: #{code}"
      end
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "returns comprehensive vulnerability information" do
      metadata = CommandInjectionExec.vulnerability_metadata()
      
      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert is_list(metadata.references)
      assert is_list(metadata.attack_vectors)
      
      # Check references include command injection resources
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
    end
    
    test "metadata includes shell injection information" do
      metadata = CommandInjectionExec.vulnerability_metadata()
      
      # Should mention shell or command injection
      assert metadata.description =~ "shell" || metadata.description =~ "command"
      
      # Should have real-world impact
      assert is_list(metadata.real_world_impact)
      assert length(metadata.real_world_impact) > 0
    end
    
    test "metadata includes safe alternatives" do
      metadata = CommandInjectionExec.vulnerability_metadata()
      
      assert Map.has_key?(metadata, :safe_alternatives)
      alternatives_text = Enum.join(metadata.safe_alternatives, " ")
      assert alternatives_text =~ "execFile"
      assert alternatives_text =~ "spawn"
    end
  end
  
  describe "applies_to_file?/2" do
    test "applies to JavaScript and TypeScript files" do
      assert CommandInjectionExec.applies_to_file?("server.js")
      assert CommandInjectionExec.applies_to_file?("api.ts")
      assert CommandInjectionExec.applies_to_file?("src/utils/exec.jsx")
      assert CommandInjectionExec.applies_to_file?("lib/commands.tsx")
    end
    
    test "applies to HTML files with embedded JavaScript" do
      html_content = """
      <script>
        const { exec } = require('child_process');
        exec('ls ' + userInput);
      </script>
      """
      assert CommandInjectionExec.applies_to_file?("admin.html", html_content)
    end
    
    test "does not apply to non-JavaScript files" do
      refute CommandInjectionExec.applies_to_file?("style.css")
      refute CommandInjectionExec.applies_to_file?("data.json")
      refute CommandInjectionExec.applies_to_file?("README.md")
      refute CommandInjectionExec.applies_to_file?("config.yml")
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns complete AST enhancement structure" do
      enhancement = CommandInjectionExec.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
    end
    
    test "AST rules specify exec/execSync patterns" do
      enhancement = CommandInjectionExec.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert is_list(enhancement.ast_rules.callee_names)
      assert "exec" in enhancement.ast_rules.callee_names
      assert "execSync" in enhancement.ast_rules.callee_names
      assert is_map(enhancement.ast_rules.argument_analysis)
    end
    
    test "context rules exclude test files and static commands" do
      enhancement = CommandInjectionExec.ast_enhancement()
      
      assert is_list(enhancement.context_rules.exclude_paths)
      assert enhancement.context_rules.exclude_if_static_command == true
      assert enhancement.context_rules.require_user_input_source == true
    end
    
    test "confidence rules provide appropriate scoring" do
      enhancement = CommandInjectionExec.ast_enhancement()
      
      assert is_number(enhancement.confidence_rules.base)
      assert is_map(enhancement.confidence_rules.adjustments)
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "has_user_input")
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "is_static_command")
      assert enhancement.min_confidence == 0.8
    end
  end
end