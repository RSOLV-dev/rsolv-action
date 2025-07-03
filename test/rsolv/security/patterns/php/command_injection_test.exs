defmodule Rsolv.Security.Patterns.Php.CommandInjectionTest do
  use ExUnit.Case, async: true
  
  alias Rsolv.Security.Patterns.Php.CommandInjection
  alias Rsolv.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = CommandInjection.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "php-command-injection"
      assert pattern.name == "Command Injection"
      assert pattern.severity == :critical
      assert pattern.type == :command_injection
      assert pattern.languages == ["php"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = CommandInjection.pattern()
      
      assert pattern.cwe_id == "CWE-78"
      assert pattern.owasp_category == "A03:2021"
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = CommandInjection.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches system() with concatenation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|system("ping " . $_GET['host']);|,
        ~S|system("ls -la " . $_POST['dir']);|,
        ~S|system('cat ' . $_REQUEST['file']);|,
        ~S|system("rm -f " . $_COOKIE['file']);|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches exec() with user input", %{pattern: pattern} do
      vulnerable_code = [
        ~S|exec("convert " . $_POST['file'] . " output.pdf");|,
        ~S|exec("grep " . $_GET['search'] . " /var/log/app.log");|,
        ~S|exec('whoami ' . $_REQUEST['args']);|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches shell_exec() with user input", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$output = shell_exec("ping -c 4 " . $_GET['host']);|,
        ~S|shell_exec('nslookup ' . $_POST['domain']);|,
        ~S|$result = shell_exec("df -h " . $_REQUEST['path']);|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches passthru() with user input", %{pattern: pattern} do
      vulnerable_code = [
        ~S|passthru("zip -r archive.zip " . $_GET['files']);|,
        ~S|passthru('tar -czf backup.tar.gz ' . $_POST['dir']);|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches backtick operator with user input", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$output = `ls $_GET[dir]`;|,
        ~S|$result = `ping -c 1 $_POST[host]`;|,
        ~S|echo `cat $_REQUEST[file]`;|,
        ~S|$data = `grep "$_COOKIE[search]" /etc/passwd`;|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches complex command injection patterns", %{pattern: pattern} do
      vulnerable_code = [
        ~S|system("echo " . $_GET['msg'] . " >> log.txt");|,
        ~S|exec("mysql -u root -p" . $_POST['pass'] . " < dump.sql");|,
        ~S|$output = `find / -name "*$_GET[pattern]*"`;|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe code with escapeshellarg", %{pattern: pattern} do
      safe_code = [
        ~S|$host = escapeshellarg($_GET['host']); system("ping " . $host);|,
        ~S|$file = escapeshellarg($_POST['file']); exec("cat " . $file);|,
        ~S|system("ls -la /safe/path");|,
        ~S|exec("whoami");|
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should not match: #{code}"
      end
    end
    
    test "matches even in comments (AST will filter)", %{pattern: pattern} do
      # Regex patterns can't easily distinguish comments
      # AST analysis handles this in production
      comment_code = [
        ~S|// system("ping " . $_GET['host']);|
      ]
      
      for code <- comment_code do
        # Comments with the actual pattern will match
        assert Regex.match?(pattern.regex, code),
               "Regex matches comments (filtered by AST): #{code}"
      end
    end
  end
  
  describe "test_cases/0" do
    test "all positive cases match" do
      pattern = CommandInjection.pattern()
      test_cases = CommandInjection.test_cases()
      
      for test_case <- test_cases.positive do
        assert Regex.match?(pattern.regex, test_case.code),
               "Failed to match positive case: #{test_case.description}"
      end
    end
    
    test "negative cases are documented correctly" do
      test_cases = CommandInjection.test_cases()
      
      # Verify we have negative test cases documented
      assert length(test_cases.negative) > 0
      
      # Each negative case should have code and description
      for test_case <- test_cases.negative do
        assert Map.has_key?(test_case, :code)
        assert Map.has_key?(test_case, :description)
      end
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = CommandInjection.ast_enhancement()
      
      assert enhancement.min_confidence == 0.95
      assert length(enhancement.ast_rules) == 3
      
      command_context_rule = Enum.find(enhancement.ast_rules, &(&1.type == "command_context"))
      assert "system" in command_context_rule.functions
      assert "exec" in command_context_rule.functions
      assert "shell_exec" in command_context_rule.functions
      
      escaping_rule = Enum.find(enhancement.ast_rules, &(&1.type == "input_escaping"))
      assert "escapeshellarg" in escaping_rule.escape_functions
      assert "escapeshellcmd" in escaping_rule.escape_functions
      
      safe_alternatives_rule = Enum.find(enhancement.ast_rules, &(&1.type == "safe_alternatives"))
      assert "proc_open" in safe_alternatives_rule.functions
      assert "pcntl_exec" in safe_alternatives_rule.functions
    end
  end
  
  describe "pattern metadata" do
    test "has proper OWASP reference" do
      pattern = CommandInjection.pattern()
      assert pattern.owasp_category == "A03:2021"
    end
    
    test "has educational content" do
      desc = CommandInjection.vulnerability_description()
      assert desc =~ "CVE"
      assert desc =~ "command injection"
      assert desc =~ "remote code execution"
    end
    
    test "provides safe alternatives" do
      examples = CommandInjection.examples()
      assert Map.has_key?(examples.fixed, "Using escapeshellarg()")
      assert Map.has_key?(examples.fixed, "Avoiding shell commands")
      assert Map.has_key?(examples.fixed, "Using PHP built-in functions")
    end
  end
end