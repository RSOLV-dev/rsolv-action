defmodule RsolvApi.Security.Patterns.Python.WeakHashSha1Test do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Python.WeakHashSha1
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = WeakHashSha1.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "python-weak-hash-sha1"
      assert pattern.name == "Weak Cryptographic Hash - SHA1"
      assert pattern.severity == :medium
      assert pattern.type == :weak_crypto
      assert pattern.languages == ["python"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = WeakHashSha1.pattern()
      
      assert pattern.cwe_id == "CWE-328"
      assert pattern.owasp_category == "A02:2021"
    end
    
    # CVE examples are stored in vulnerability_description now
  end
  
  describe "regex matching" do
    setup do
      pattern = WeakHashSha1.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches direct hashlib.sha1() usage", %{pattern: pattern} do
      vulnerable_code = [
        "hashlib.sha1(data)",
        "hashlib.sha1(message.encode())",
        "hashlib.sha1()",
        "signature = hashlib.sha1(secret)",
        "return hashlib.sha1(content).hexdigest()"
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches SHA1 imports", %{pattern: pattern} do
      vulnerable_code = [
        "from hashlib import sha1",
        "from hashlib import md5, sha1",
        "from hashlib import sha1, sha256"
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches SHA1 instance creation", %{pattern: pattern} do
      vulnerable_code = [
        "h = sha1()",
        "hasher = hashlib.sha1()",
        "sha1_hash = hashlib.sha1()"
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches crypto.new with sha1", %{pattern: pattern} do
      vulnerable_code = [
        "Crypto.Hash.new('sha1')",
        "h = Hash.new(\"sha1\")"
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches even in comments (AST will filter)", %{pattern: pattern} do
      # Regex patterns can't easily distinguish comments
      # AST analysis handles this in production
      comment_code = [
        "# Don't use hashlib.sha1()"
      ]
      
      for code <- comment_code do
        # Comments with the actual pattern will match
        assert Regex.match?(pattern.regex, code),
               "Regex matches comments (filtered by AST): #{code}"
      end
    end
    
    test "does not match other hash algorithms", %{pattern: pattern} do
      safe_code = [
        "hashlib.sha256(data)",
        "hashlib.sha512(password)",
        "hashlib.sha3_256(secret)",
        "from hashlib import sha256"
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should not match: #{code}"
      end
    end
  end
  
  describe "test_cases/0" do
    test "all positive cases match" do
      pattern = WeakHashSha1.pattern()
      test_cases = WeakHashSha1.test_cases()
      
      for test_case <- test_cases.positive do
        assert Regex.match?(pattern.regex, test_case),
               "Failed to match positive case: #{test_case}"
      end
    end
    
    test "all negative cases don't match" do
      pattern = WeakHashSha1.pattern()
      test_cases = WeakHashSha1.test_cases()
      
      for test_case <- test_cases.negative do
        refute Regex.match?(pattern.regex, test_case),
               "Should not match negative case: #{test_case}"
      end
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = WeakHashSha1.ast_enhancement()
      
      assert enhancement.min_confidence == 0.75
      assert length(enhancement.rules) == 2
      
      context_rule = Enum.find(enhancement.rules, &(&1.type == "context_check"))
      assert "git_hash" in context_rule.checks
      assert "legacy_system" in context_rule.checks
      
      severity_rule = Enum.find(enhancement.rules, &(&1.type == "severity_increase"))
      assert "signature" in severity_rule.contexts
      assert "certificate" in severity_rule.contexts
    end
  end
  
  describe "pattern metadata" do
    test "has proper OWASP reference" do
      pattern = WeakHashSha1.pattern()
      assert pattern.owasp_category == "A02:2021"
    end
    
    test "has educational content" do
      desc = WeakHashSha1.vulnerability_description()
      assert desc =~ "SHAttered Attack"
      assert desc =~ "Collision Attacks"
      assert desc =~ "NIST formally deprecated"
    end
    
    test "provides safe alternatives" do
      examples = WeakHashSha1.examples()
      assert Map.has_key?(examples.fixed, "Use SHA-256 for signatures")
      assert Map.has_key?(examples.fixed, "Use HMAC-SHA256")
    end
  end
end