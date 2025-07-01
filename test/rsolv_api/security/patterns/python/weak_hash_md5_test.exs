defmodule RsolvApi.Security.Patterns.Python.WeakHashMd5Test do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Python.WeakHashMd5
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = WeakHashMd5.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "python-weak-hash-md5"
      assert pattern.name == "Weak Cryptographic Hash - MD5"
      assert pattern.severity == :medium
      assert pattern.type == :weak_crypto
      assert pattern.languages == ["python"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = WeakHashMd5.pattern()
      
      assert pattern.cwe_id == "CWE-328"
      assert pattern.owasp_category == "A02:2021"
    end
    
    # CVE examples are stored in vulnerability_description now
  end
  
  describe "regex matching" do
    setup do
      pattern = WeakHashMd5.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches direct hashlib.md5() usage", %{pattern: pattern} do
      vulnerable_code = [
        "hashlib.md5(data)",
        "hashlib.md5(password.encode())",
        "hashlib.md5()",
        "hash = hashlib.md5(input_data)",
        "return hashlib.md5(secret).hexdigest()"
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches MD5 imports", %{pattern: pattern} do
      vulnerable_code = [
        "from hashlib import md5",
        "from hashlib import sha1, md5",
        "from hashlib import md5, sha256"
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches MD5 instance creation", %{pattern: pattern} do
      vulnerable_code = [
        "h = md5()",
        "hasher = hashlib.md5()",
        "md5_hash = hashlib.md5()"
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches crypto.new with md5", %{pattern: pattern} do
      vulnerable_code = [
        "Crypto.Hash.new('md5')",
        "h = Hash.new(\"md5\")"
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
        "# Don't use hashlib.md5()"
      ]
      
      for code <- comment_code do
        # The first one matches, the second doesn't contain the pattern
        if code =~ "hashlib.md5" do
          assert Regex.match?(pattern.regex, code),
                 "Regex matches comments with pattern: #{code}"
        else
          refute Regex.match?(pattern.regex, code),
                 "Regex doesn't match comments without pattern: #{code}"
        end
      end
    end
    
    test "does not match other hash algorithms", %{pattern: pattern} do
      safe_code = [
        "hashlib.sha256(data)",
        "hashlib.sha512(password)",
        "hashlib.blake2b(secret)",
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
      pattern = WeakHashMd5.pattern()
      test_cases = WeakHashMd5.test_cases()
      
      for test_case <- test_cases.positive do
        assert Regex.match?(pattern.regex, test_case),
               "Failed to match positive case: #{test_case}"
      end
    end
    
    test "all negative cases don't match" do
      pattern = WeakHashMd5.pattern()
      test_cases = WeakHashMd5.test_cases()
      
      for test_case <- test_cases.negative do
        refute Regex.match?(pattern.regex, test_case),
               "Should not match negative case: #{test_case}"
      end
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = WeakHashMd5.ast_enhancement()
      
      assert enhancement.min_confidence == 0.7
      assert length(enhancement.ast_rules) == 2
      
      context_rule = Enum.find(enhancement.ast_rules, &(&1.type == "context_check"))
      assert "file_checksum" in context_rule.checks
      assert "cache_key" in context_rule.checks
      
      severity_rule = Enum.find(enhancement.ast_rules, &(&1.type == "severity_increase"))
      assert "password" in severity_rule.contexts
      assert "token" in severity_rule.contexts
    end
  end
  
  describe "pattern metadata" do
    test "has proper OWASP reference" do
      pattern = WeakHashMd5.pattern()
      assert pattern.owasp_category == "A02:2021"
    end
    
    test "has educational content" do
      desc = WeakHashMd5.vulnerability_description()
      assert desc =~ "Collision Attacks"
      assert desc =~ "Rainbow Tables"
      assert desc =~ "Flame Malware"
    end
    
    test "provides safe alternatives" do
      examples = WeakHashMd5.examples()
      assert Map.has_key?(examples.fixed, "Use SHA-256 for hashing")
      assert Map.has_key?(examples.fixed, "Use proper password hashing")
    end
  end
end