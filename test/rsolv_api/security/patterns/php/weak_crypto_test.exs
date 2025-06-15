defmodule RsolvApi.Security.Patterns.Php.WeakCryptoTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Php.WeakCrypto
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = WeakCrypto.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "php-weak-crypto"
      assert pattern.name == "Weak Cryptography"
      assert pattern.severity == :medium
      assert pattern.type == :weak_crypto
      assert pattern.languages == ["php"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = WeakCrypto.pattern()
      
      assert pattern.cwe_id == "CWE-327"
      assert pattern.owasp_category == "A02:2021"
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = WeakCrypto.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches mcrypt functions", %{pattern: pattern} do
      vulnerable_code = [
        ~S|mcrypt_encrypt(MCRYPT_DES, $key, $data, MCRYPT_MODE_ECB);|,
        ~S|mcrypt_decrypt(MCRYPT_3DES, $key, $data, MCRYPT_MODE_CBC);|,
        ~S|mcrypt_generic($handle, $data);|,
        ~S|mcrypt_enc_self_test($handle);|,
        ~S|mcrypt_module_open(MCRYPT_DES, '', MCRYPT_MODE_ECB, '');|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches weak mcrypt constants", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$cipher = MCRYPT_DES;|,
        ~S|$algorithm = MCRYPT_3DES;|,
        ~S|$mode = MCRYPT_MODE_ECB;|,
        ~S|mcrypt_encrypt(MCRYPT_DES, $key, $data, MCRYPT_MODE_ECB);|,
        ~S|if ($alg == MCRYPT_3DES) { /* weak crypto */ }|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches ECB mode in openssl", %{pattern: pattern} do
      vulnerable_code = [
        ~S|openssl_encrypt($data, 'aes-128-ecb', $key);|,
        ~S|openssl_decrypt($data, 'des-ecb', $key);|,
        ~S|$method = 'aes-256-ecb';|,
        ~S|openssl_encrypt($plaintext, 'DES-ECB', $password);|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches DES algorithms", %{pattern: pattern} do
      vulnerable_code = [
        ~S|openssl_encrypt($data, 'des-cbc', $key);|,
        ~S|openssl_encrypt($data, 'des-ede3', $key);|,
        ~S|$cipher = 'DES-CFB';|,
        ~S|openssl_decrypt($encrypted, 'des-ofb', $key);|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches various spacing and formatting", %{pattern: pattern} do
      vulnerable_code = [
        ~S|mcrypt_encrypt( MCRYPT_DES, $key, $data, MCRYPT_MODE_ECB );|,
        ~S|openssl_encrypt($data, "aes-128-ecb", $key);|,
        ~S|$alg=MCRYPT_3DES;|,
        ~S|use_cipher('des-ecb');|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe operations", %{pattern: pattern} do
      safe_code = [
        ~S|openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv, $tag);|,
        ~S|openssl_encrypt($data, 'aes-128-cbc', $key, 0, $iv);|,
        ~S|$cipher = 'aes-256-ctr';|,
        ~S|sodium_crypto_secretbox($message, $nonce, $key);|,
        ~S|hash('sha256', $data);|,
        ~S|password_hash($password, PASSWORD_ARGON2ID);|,
        ~S|random_bytes(32);|
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should not match: #{code}"
      end
    end
    
    test "matches real-world vulnerable patterns", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$encrypted = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_ECB);|,
        ~S|$legacy_cipher = MCRYPT_DES; mcrypt_encrypt($legacy_cipher, $key, $data, MCRYPT_MODE_CBC);|,
        ~S|openssl_encrypt($sensitive_data, 'des-ede3-ecb', $encryption_key);|,
        ~S|if ($use_legacy) { $result = mcrypt_generic($handle, $plaintext); }|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
  end
  
  describe "test_cases/0" do
    test "all positive cases match" do
      pattern = WeakCrypto.pattern()
      test_cases = WeakCrypto.test_cases()
      
      for test_case <- test_cases.positive do
        assert Regex.match?(pattern.regex, test_case.code),
               "Failed to match positive case: #{test_case.description}"
      end
    end
    
    test "negative cases are documented correctly" do
      test_cases = WeakCrypto.test_cases()
      
      assert length(test_cases.negative) > 0
      
      for test_case <- test_cases.negative do
        assert Map.has_key?(test_case, :code)
        assert Map.has_key?(test_case, :description)
      end
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = WeakCrypto.ast_enhancement()
      
      assert enhancement.min_confidence >= 0.6
      assert length(enhancement.rules) >= 3
      
      crypto_functions_rule = Enum.find(enhancement.rules, &(&1.type == "weak_crypto_functions"))
      assert crypto_functions_rule
      assert "mcrypt_encrypt" in crypto_functions_rule.functions
      assert "openssl_encrypt" in crypto_functions_rule.functions
      
      algorithm_rule = Enum.find(enhancement.rules, &(&1.type == "crypto_algorithm_analysis"))
      assert algorithm_rule
      assert "DES" in algorithm_rule.weak_algorithms
      assert "ECB" in algorithm_rule.weak_modes
    end
  end
  
  describe "pattern metadata" do
    test "has proper OWASP reference" do
      pattern = WeakCrypto.pattern()
      assert pattern.owasp_category == "A02:2021"
    end
    
    test "has educational content" do
      desc = WeakCrypto.vulnerability_description()
      assert desc =~ "Weak cryptography"
      assert desc =~ "mcrypt"
      assert desc =~ "deprecated"
    end
    
    test "provides safe alternatives" do
      examples = WeakCrypto.examples()
      assert Map.has_key?(examples.fixed, "Modern encryption")
      assert Map.has_key?(examples.fixed, "Secure algorithms")
    end
  end
end