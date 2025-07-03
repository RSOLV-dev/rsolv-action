defmodule Rsolv.Security.Patterns.Java.CommandInjectionRuntimeExecTest do
  use ExUnit.Case, async: true
  
  alias Rsolv.Security.Patterns.Java.CommandInjectionRuntimeExec
  alias Rsolv.Security.Pattern
  
  test "pattern returns correct structure" do
    pattern = CommandInjectionRuntimeExec.pattern()
    
    assert %Pattern{} = pattern
    assert pattern.id == "java-command-injection-runtime-exec"
    assert pattern.name == "Command Injection via Runtime.exec"
    assert pattern.severity == :critical
    assert pattern.type == :command_injection
    assert pattern.languages == ["java"]
    assert pattern.cwe_id == "CWE-78"
    assert pattern.owasp_category == "A03:2021"
    assert is_list(pattern.regex)
    assert length(pattern.regex) >= 5
  end
  
  test "detects command injection patterns" do
    pattern = CommandInjectionRuntimeExec.pattern()
    
    # Test basic concatenation
    code1 = "Runtime.getRuntime().exec(\"ping \" + hostname);"
    assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code1) end)
    
    # Test String.format
    code2 = "Runtime.getRuntime().exec(String.format(\"ping %s\", host));"
    assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code2) end)
    
    # Test variable pattern
    code3 = "String cmd = \"ping \" + hostname;"
    assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code3) end)
    
    # Test StringBuilder
    code4 = "StringBuilder cmd = new StringBuilder(\"ping \");"
    assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code4) end)
    
    # Test shell array
    code5 = "runtime.exec(new String[]{\"bash\", \"-c\", script + args});"
    assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code5) end)
    
    # Test pipeline
    code6 = "Runtime.getRuntime().exec(\"cat \" + file + \" | grep test\");"
    assert Enum.any?(pattern.regex, fn r -> Regex.match?(r, code6) end)
    
    # Should not match safe code
    safe1 = "Runtime.getRuntime().exec(\"ping 127.0.0.1\");"
    refute Enum.any?(pattern.regex, fn r -> Regex.match?(r, safe1) end)
    
    safe2 = "Runtime.getRuntime().exec(new String[]{\"ping\", \"127.0.0.1\"});"
    refute Enum.any?(pattern.regex, fn r -> Regex.match?(r, safe2) end)
  end
  
  test "vulnerability metadata is comprehensive" do
    metadata = CommandInjectionRuntimeExec.vulnerability_metadata()
    
    assert String.contains?(String.downcase(metadata.description), "command injection")
    assert length(metadata.references) >= 4
    assert length(metadata.attack_vectors) >= 5
    assert length(metadata.real_world_impact) >= 4
    assert length(metadata.cve_examples) >= 3
    
    cve_ids = Enum.map(metadata.cve_examples, fn cve -> cve.id end)
    assert Enum.any?(cve_ids, fn id -> String.contains?(id, "CVE-") end)
    assert Enum.any?(cve_ids, fn id -> String.contains?(id, "2017-5638") end)
  end
  
  test "ast enhancement is configured" do
    enhancement = CommandInjectionRuntimeExec.ast_enhancement()
    
    assert Map.has_key?(enhancement, :ast_rules)
    assert Map.has_key?(enhancement, :context_rules)
    assert Map.has_key?(enhancement, :confidence_rules)
    assert Map.has_key?(enhancement, :min_confidence)
    
    assert enhancement.min_confidence >= 0.7
    assert enhancement.ast_rules.node_type == "MethodInvocation"
    assert enhancement.ast_rules.exec_analysis.check_method_name
    assert enhancement.ast_rules.shell_detection.check_shell_invocation
    assert enhancement.context_rules.check_constant_commands
  end
end