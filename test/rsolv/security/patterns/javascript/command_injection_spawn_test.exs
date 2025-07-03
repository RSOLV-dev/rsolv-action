defmodule Rsolv.Security.Patterns.Javascript.CommandInjectionSpawnTest do
  use ExUnit.Case, async: true
  doctest Rsolv.Security.Patterns.Javascript.CommandInjectionSpawn
  
  alias Rsolv.Security.Patterns.Javascript.CommandInjectionSpawn
  alias Rsolv.Security.Pattern
  
  # Test helpers for better readability
  defp get_pattern, do: CommandInjectionSpawn.pattern()
  
  defp assert_matches_code(pattern, code) do
    assert Regex.match?(pattern.regex, code), 
      "Pattern should match vulnerable code: #{code}"
  end
  
  defp refute_matches_code(pattern, code) do
    refute Regex.match?(pattern.regex, code),
      "Pattern should NOT match safe code: #{code}"
  end
  
  defp vulnerable_spawn_patterns do
    [
      # Basic shell:true patterns
      ~S|spawn("sh", ["-c", userInput], {shell: true})|,
      ~S|spawn(cmd, {shell: true, cwd: req.body.path})|,
      ~S|spawn("bash", ["-c", `echo ${userData}`], {shell: true})|,
      
      # Different shell executables
      ~S|spawn("powershell", [userScript], {shell: true})|,
      ~S|spawn("cmd", ["/c", params.script], {shell: true})|,
      ~S|spawn("zsh", ["-c", scriptContent], {shell: true})|,
      
      # Different option combinations
      ~S|spawn(req.body.command, [], {shell: true, stdio: 'inherit'})|,
      ~S|spawn(executable, arguments, {shell: true, env: process.env})|,
      ~S|spawn(userCommand, {shell: true, detached: false})|,
      ~S|spawn("bash", args, {shell: true, timeout: 5000})|,
      
      # Advanced patterns
      ~S|const proc = spawn("sh", ["-c", input], {shell: true})|,
      ~S|spawn(`${command}`, [], {shell: true})|,
      ~S|spawn(process, cmdArgs, {shell: true, windowsHide: true})|,
      ~S|spawn(binaryPath, parameters, {shell: true, uid: 1000})|
    ]
  end
  
  defp safe_spawn_patterns do
    [
      # Direct execution without shell
      ~S|spawn("echo", [userData])|,
      ~S|spawn("ls", ["-la", directory])|,
      ~S|spawn("python", [scriptPath, arg1, arg2])|,
      ~S|spawn("java", ["-jar", jarFile], {cwd: workDir})|,
      
      # Explicit shell:false
      ~S|spawn("node", ["script.js"], {shell: false})|,
      ~S|spawn("echo", validatedArgs, {shell: false})|,
      
      # Alternative functions
      ~S|execFile("git", ["status"], {cwd: safePath})|,
      ~S|spawnSync("echo", ["hello world"])|,
      ~S|child_process.exec(command) // different function|,
      
      # Without shell option (default is false)
      ~S|spawn(command, args) // no shell option|,
      ~S|spawn("git", ["clone", repoUrl], {stdio: 'inherit'})|,
      ~S|spawn("docker", ["run", imageName], {detached: true})|,
      ~S|spawn("npm", ["install"], {cwd: projectDir})|,
      ~S|spawn("curl", ["-X", "GET", apiUrl])|,
      ~S|spawn(validatedCommand, sanitizedArgs)|
    ]
  end
  
  describe "CommandInjectionSpawn pattern" do
    test "returns correct pattern structure with all required fields" do
      pattern = get_pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-command-injection-spawn"
      assert pattern.name == "Command Injection via spawn with shell"
      assert pattern.description == "Using spawn with shell:true and user input enables command injection"
      assert pattern.type == :command_injection
      assert pattern.severity == :critical
      assert pattern.languages == ["javascript", "typescript"]
      assert pattern.cwe_id == "CWE-78"
      assert pattern.owasp_category == "A03:2021"
      assert is_binary(pattern.recommendation)
      assert is_map(pattern.test_cases)
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
    end
    
    test "detects all categories of vulnerable spawn() usage with shell:true" do
      pattern = get_pattern()
      
      for code <- vulnerable_spawn_patterns() do
        assert_matches_code(pattern, code)
      end
    end
    
    test "does not match safe spawn() alternatives and related functions" do
      pattern = get_pattern()
      
      for code <- safe_spawn_patterns() do
        refute_matches_code(pattern, code)
      end
    end
    
    test "provides comprehensive vulnerability metadata with proper structure" do
      metadata = CommandInjectionSpawn.vulnerability_metadata()
      
      # Basic structure validation
      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert String.length(metadata.description) > 100
      
      # Validate authoritative references
      assert is_list(metadata.references)
      assert length(metadata.references) >= 4
      
      valid_reference_types = [:cwe, :owasp, :nist, :research, :sans, :vendor]
      for ref <- metadata.references do
        assert Map.has_key?(ref, :type)
        assert Map.has_key?(ref, :url)
        assert ref.type in valid_reference_types
        assert String.starts_with?(ref.url, "http")
      end
      
      # Validate attack methodology documentation
      assert is_list(metadata.attack_vectors) and length(metadata.attack_vectors) >= 5
      assert is_list(metadata.real_world_impact) and length(metadata.real_world_impact) >= 5
      assert is_list(metadata.safe_alternatives) and length(metadata.safe_alternatives) >= 5
      
      # Validate CVE examples with proper severity classification
      assert is_list(metadata.cve_examples)
      assert length(metadata.cve_examples) >= 3
      
      valid_severities = ["low", "medium", "high", "critical"]
      for cve <- metadata.cve_examples do
        assert Map.has_key?(cve, :id)
        assert Map.has_key?(cve, :description)
        assert Map.has_key?(cve, :severity)
        assert String.starts_with?(cve.id, "CVE-")
        assert cve.severity in valid_severities
      end
      
      # Validate detection methodology documentation
      assert is_binary(metadata.detection_notes)
      assert String.length(metadata.detection_notes) > 50
    end
    
    test "correctly identifies applicable file types for JavaScript and TypeScript" do
      # JavaScript and TypeScript files should be detected
      javascript_files = ["test.js", "app.jsx", "server.ts", "component.tsx", "module.mjs"]
      for file <- javascript_files do
        assert CommandInjectionSpawn.applies_to_file?(file, nil),
          "Should apply to JavaScript file: #{file}"
      end
      
      # Other language files should be rejected
      other_language_files = ["test.py", "app.rb", "server.php", "component.vue", "script.sh"]
      for file <- other_language_files do
        refute CommandInjectionSpawn.applies_to_file?(file, nil),
          "Should NOT apply to non-JavaScript file: #{file}"
      end
    end
    
  end
  
  describe "ast_enhancement/0" do
    test "returns complete AST enhancement structure" do
      enhancement = CommandInjectionSpawn.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
    end
    
    test "AST rules specify spawn call patterns" do
      enhancement = CommandInjectionSpawn.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert enhancement.ast_rules.callee_names == ["spawn", "spawnSync"]
      assert is_map(enhancement.ast_rules.option_analysis)
      assert enhancement.ast_rules.option_analysis.has_shell_true == true
    end
    
    test "context rules include shell option checks" do
      enhancement = CommandInjectionSpawn.ast_enhancement()
      
      assert is_list(enhancement.context_rules.exclude_paths)
      assert enhancement.context_rules.safe_if_no_shell == true
      assert enhancement.context_rules.safe_if_array_command == true
    end
    
    test "confidence rules provide appropriate scoring" do
      enhancement = CommandInjectionSpawn.ast_enhancement()
      
      assert is_number(enhancement.confidence_rules.base)
      assert is_map(enhancement.confidence_rules.adjustments)
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "has_shell_true")
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "command_has_user_input")
      assert enhancement.min_confidence == 0.8
    end
  end
end