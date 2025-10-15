defmodule Rsolv.Security.Patterns.Ruby.CommandInjectionTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Ruby.CommandInjection
  alias Rsolv.Security.Pattern

  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = CommandInjection.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "ruby-command-injection"
      assert pattern.name == "Command Injection"
      assert pattern.severity == :critical
      assert pattern.type == :command_injection
      assert pattern.languages == ["ruby"]
    end

    test "includes CWE and OWASP references" do
      pattern = CommandInjection.pattern()

      assert pattern.cwe_id == "CWE-78"
      assert pattern.owasp_category == "A03:2021"
    end

    test "has multiple regex patterns" do
      pattern = CommandInjection.pattern()

      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 6
    end
  end

  describe "regex matching" do
    setup do
      pattern = CommandInjection.pattern()
      {:ok, pattern: pattern}
    end

    test "matches system calls with interpolation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|system("ls #{params[:dir]}")|,
        ~S|system("cat #{filename}")|,
        ~S|system("rm -rf #{path}")|,
        ~S|system("git clone #{repo_url}")|,
        ~S|system("wget #{url}")|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches backtick command execution", %{pattern: pattern} do
      vulnerable_code = [
        ~S|`cat #{filename}`|,
        ~S|`ls #{directory}`|,
        ~S|`curl #{url}`|,
        ~S|`ping #{host}`|,
        ~S|result = `whoami #{params[:user]}`|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches exec calls with interpolation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|exec("rm #{file}")|,
        ~S|exec("cat #{path}/config")|,
        ~S|exec("bash #{script_name}")|,
        ~S|Kernel.exec("kill #{pid}")|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches %x percent-x notation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|%x{ls #{dir}}|,
        ~S|%x[cat #{file}]|,
        ~S|%x(echo #{message})|,
        ~S|%x/grep #{pattern} file/|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches IO.popen with interpolation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|IO.popen("cat #{file}")|,
        ~S|IO.popen("ls #{directory}", "r")|,
        ~S|pipe = IO.popen("grep #{pattern} #{file}")|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches Open3 methods with interpolation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|Open3.capture2("ls #{dir}")|,
        ~S|Open3.capture3("cat #{file}")|,
        ~S|Open3.popen3("git clone #{url}")|,
        ~S|Open3.pipeline("cat #{file}", "grep pattern")|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "does not match safe command execution patterns", %{pattern: pattern} do
      safe_code = [
        ~S|system("ls", params[:dir])|,
        ~S|system("cat", Shellwords.escape(filename))|,
        ~S|Open3.capture2("ls", "-la", dir)|,
        ~S|exec("static_command")|,
        ~S|`static command`|,
        ~S|puts "Running command: #{cmd}"|,
        ~S|system("ls")|
      ]

      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should not match: #{code}"
      end
    end

    test "documents regex limitations for comment detection" do
      # NOTE: This pattern has a known limitation - it will match commented-out code
      # This is acceptable because AST enhancement will filter out comments in practice
      commented_code = ~S|# system("rm #{file}")|
      pattern = CommandInjection.pattern()

      # This will match, but AST enhancement filters it out
      assert Enum.any?(pattern.regex, &Regex.match?(&1, commented_code)),
             "Expected regex limitation: matches comments (filtered by AST)"
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = CommandInjection.vulnerability_metadata()

      assert metadata.description =~ "Command injection"
      assert length(metadata.references) >= 3
      assert length(metadata.attack_vectors) >= 5
      assert length(metadata.real_world_impact) >= 3
      assert length(metadata.cve_examples) >= 3
    end

    test "includes real-world incident references" do
      metadata = CommandInjection.vulnerability_metadata()

      impact = Enum.join(metadata.real_world_impact, " ")
      assert impact =~ "CVE-2021-31799" || impact =~ "CVE-2017-17405" || impact =~ "RDoc"
    end

    test "includes proper references" do
      metadata = CommandInjection.vulnerability_metadata()

      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = CommandInjection.ast_enhancement()

      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)

      assert enhancement.min_confidence >= 0.7
    end

    test "includes command-specific AST rules" do
      enhancement = CommandInjection.ast_enhancement()

      assert enhancement.ast_rules.node_type == "CallExpression"
      assert "system" in enhancement.ast_rules.method_names
    end

    test "has proper context detection" do
      enhancement = CommandInjection.ast_enhancement()

      assert enhancement.context_rules.check_shell_context
      assert "Shellwords.escape" in enhancement.context_rules.safe_functions
    end
  end
end
