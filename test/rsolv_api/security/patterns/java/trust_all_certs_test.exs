defmodule RsolvApi.Security.Patterns.Java.TrustAllCertsTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Java.TrustAllCerts
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = TrustAllCerts.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "java-trust-all-certs"
      assert pattern.name == "Trust All Certificates"
      assert pattern.severity == :critical
      assert pattern.type == :authentication
      assert pattern.languages == ["java"]
      assert pattern.cwe_id == "CWE-295"
      assert pattern.owasp_category == "A07:2021"
      assert is_struct(pattern.regex, Regex) or is_list(pattern.regex)
      assert pattern.default_tier == :ai
    end
    
    test "includes comprehensive test cases" do
      pattern = TrustAllCerts.pattern()
      
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
      assert is_list(pattern.test_cases.vulnerable)
      assert is_list(pattern.test_cases.safe)
      assert length(pattern.test_cases.vulnerable) >= 2
      assert length(pattern.test_cases.safe) >= 2
    end
    
    test "has appropriate recommendation" do
      pattern = TrustAllCerts.pattern()
      
      assert String.contains?(String.downcase(pattern.recommendation), "certificate") or
             String.contains?(String.downcase(pattern.recommendation), "validation")
      assert String.contains?(String.downcase(pattern.recommendation), "proper") or
             String.contains?(String.downcase(pattern.recommendation), "implement")
    end
  end
  
  describe "regex matching" do
    test "detects empty checkClientTrusted implementation" do
      pattern = TrustAllCerts.pattern()
      
      vulnerable_code = [
        "new X509TrustManager() { public void checkClientTrusted(X509Certificate[] chain, String authType) {} }",
        "public void checkClientTrusted(X509Certificate[] certs, String authType) {}",
        "checkClientTrusted(X509Certificate[] chain, String authType) { }",
        "public void checkClientTrusted(X509Certificate[] certificates, String auth) { /* empty */ }",
        "void checkClientTrusted(X509Certificate[] certs, String type) { return; }",
        "@Override public void checkClientTrusted(X509Certificate[] chain, String authType) {}"
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects empty checkServerTrusted implementation" do
      pattern = TrustAllCerts.pattern()
      
      vulnerable_code = [
        "new X509TrustManager() { public void checkServerTrusted(X509Certificate[] chain, String authType) {} }",
        "public void checkServerTrusted(X509Certificate[] certs, String authType) {}",
        "checkServerTrusted(X509Certificate[] chain, String authType) { }",
        "public void checkServerTrusted(X509Certificate[] certificates, String auth) { /* empty */ }",
        "void checkServerTrusted(X509Certificate[] certs, String type) { return; }",
        "@Override public void checkServerTrusted(X509Certificate[] chain, String authType) {}"
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects TrustManager with empty implementation" do
      pattern = TrustAllCerts.pattern()
      
      vulnerable_code = [
        "TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() { public void checkClientTrusted(X509Certificate[] chain, String authType) {} } };",
        "TrustManager trustManager = new X509TrustManager() { public void checkServerTrusted(X509Certificate[] certs, String authType) {} };",
        "new TrustManager[] { new X509TrustManager() { public void checkClientTrusted(X509Certificate[] c, String a) {} } }",
        "X509TrustManager trustAll = new X509TrustManager() { public void checkServerTrusted(X509Certificate[] chain, String authType) {} };",
        "implements X509TrustManager { public void checkClientTrusted(X509Certificate[] certs, String authType) {} }",
        "class TrustAllManager implements X509TrustManager { public void checkServerTrusted(X509Certificate[] chain, String authType) {} }",
        "extends X509TrustManager { public void checkClientTrusted(X509Certificate[] certificates, String auth) {} }"
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects various empty method patterns" do
      pattern = TrustAllCerts.pattern()
      
      vulnerable_code = [
        "public void checkClientTrusted(X509Certificate[] chain, String authType) { /* TODO: implement */ }",
        "public void checkClientTrusted(X509Certificate[] chain, String authType) { return; }",
        "checkServerTrusted(X509Certificate[] certificates, String authType) { /* accept all */ }",
        "void checkClientTrusted(X509Certificate[] certs, String auth) { /* trust everything */ }",
        "checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException { }"
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects HostnameVerifier that accepts all" do
      pattern = TrustAllCerts.pattern()
      
      vulnerable_code = [
        "HostnameVerifier allHostsValid = new HostnameVerifier() { public boolean verify(String hostname, SSLSession session) { return true; } };",
        "new HostnameVerifier() { public boolean verify(String hostname, SSLSession session) { return true; } }",
        "public boolean verify(String hostname, SSLSession session) { return true; }",
        "HostnameVerifier trustAll = (hostname, session) -> true;",
        "setDefaultHostnameVerifier(new HostnameVerifier() { public boolean verify(String h, SSLSession s) { return true; } });",
        "boolean verify(String hostname, SSLSession session) { return true; }",
        "@Override public boolean verify(String hostname, SSLSession session) { return true; }"
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects SSL context with trust all configuration" do
      pattern = TrustAllCerts.pattern()
      
      vulnerable_code = [
        "SSLContext.getInstance(\"SSL\").init(null, trustAllCerts, new java.security.SecureRandom());",
        "sslContext.init(null, new TrustManager[] { trustAllManager }, null);",
        "SSLContext context = SSLContext.getInstance(\"TLS\"); context.init(null, trustAllCerts, new SecureRandom());",
        "context.init(null, new TrustManager[] { new X509TrustManager() {} }, null);",
        "HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());",
        "HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);"
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "does not match secure certificate validation implementations" do
      pattern = TrustAllCerts.pattern()
      
      safe_code = [
        "public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException { validateCertificateChain(chain); }",
        "public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException { if (chain == null) throw new CertificateException(); }",
        "// TrustManager[] trustAllCerts = new TrustManager[] { /* commented out */ };",
        "String example = \"checkClientTrusted(X509Certificate[] chain, String authType) {}\";",
        "public boolean verify(String hostname, SSLSession session) { return validateHostname(hostname, session); }",
        "SSLContext sslContext = SSLContext.getDefault();",
        "TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());",
        "tmf.init((KeyStore) null); TrustManager[] trustManagers = tmf.getTrustManagers();",
        "public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException { validateChain(chain, authType); }",
        "public boolean verify(String hostname, SSLSession session) { return hostname.equals(expectedHostname); }"
      ]
      
      for code <- safe_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        refute Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should not match: #{code}"
      end
    end
    
    test "detects method signatures with various spacing" do
      pattern = TrustAllCerts.pattern()
      
      vulnerable_code = [
        "public void checkClientTrusted( X509Certificate[] chain, String authType ) {}",
        "checkServerTrusted(X509Certificate[]chain,String authType){}",
        "public void checkClientTrusted(X509Certificate[] chain,String authType) { }",
        "void checkServerTrusted( X509Certificate[] certificates , String auth ) { }",
        "public void  checkClientTrusted  (X509Certificate[] chain, String authType)  {  }",
        "checkServerTrusted (X509Certificate[] certs,  String type)  {  }",
        "public void checkClientTrusted(X509Certificate[]chain,String authType){}"
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
    
    test "detects return true patterns for HostnameVerifier" do
      pattern = TrustAllCerts.pattern()
      
      vulnerable_code = [
        "public boolean verify(String hostname, SSLSession session) { return true; }",
        "boolean verify(String h, SSLSession s) { return true; }",
        "verify(String hostname, SSLSession session) { return true; }",
        "public boolean verify(String hostname, SSLSession session) { /* ignore hostname */ return true; }",
        "@Override public boolean verify(String hostname, SSLSession session) { return true; }",
      ]
      
      for code <- vulnerable_code do
        regex_list = if is_list(pattern.regex), do: pattern.regex, else: [pattern.regex]
        assert Enum.any?(regex_list, fn r -> Regex.match?(r, code) end),
               "Should match: #{code}"
      end
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = TrustAllCerts.vulnerability_metadata()
      
      assert String.contains?(String.downcase(metadata.description), "certificate") and
             String.contains?(String.downcase(metadata.description), "trust")
      assert String.contains?(String.downcase(metadata.description), "validation") or
             String.contains?(String.downcase(metadata.description), "verification")
      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 4
      assert length(metadata.real_world_impact) >= 4
      assert length(metadata.cve_examples) >= 2
    end
    
    test "includes certificate-specific information" do
      metadata = TrustAllCerts.vulnerability_metadata()
      
      assert String.contains?(metadata.description, "TrustManager") or 
             String.contains?(metadata.description, "certificate")
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "certificate")) or
             Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "validation"))
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "proper")) or
             Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "default"))
    end
    
    test "includes proper security references" do
      metadata = TrustAllCerts.vulnerability_metadata()
      
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
    
    test "includes OWASP Top 10 information" do
      metadata = TrustAllCerts.vulnerability_metadata()
      
      assert Enum.any?(metadata.references, fn ref ->
        String.contains?(String.downcase(ref.title), "owasp") and 
        String.contains?(String.downcase(ref.title), "a07")
      end)
    end
    
    test "includes CVE examples with proper structure" do
      metadata = TrustAllCerts.vulnerability_metadata()
      
      for cve <- metadata.cve_examples do
        assert Map.has_key?(cve, :id)
        assert Map.has_key?(cve, :description)
        assert Map.has_key?(cve, :severity)
        assert Map.has_key?(cve, :cvss)
        assert is_number(cve.cvss)
        assert cve.cvss > 0
      end
    end
    
    test "includes certificate-specific attack information" do
      metadata = TrustAllCerts.vulnerability_metadata()
      
      assert Enum.any?(metadata.additional_context.secure_patterns, fn pattern ->
        String.contains?(String.downcase(pattern), "certificate") or
        String.contains?(String.downcase(pattern), "validation") or
        String.contains?(String.downcase(pattern), "trustmanager")
      end)
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = TrustAllCerts.ast_enhancement()
      
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.8
    end
    
    test "includes TrustManager analysis" do
      enhancement = TrustAllCerts.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "MethodDeclaration" or
             enhancement.ast_rules.node_type == "ClassDeclaration"
      assert enhancement.ast_rules.trust_analysis.check_trust_manager
      assert enhancement.ast_rules.trust_analysis.trust_manager_methods
      assert enhancement.ast_rules.trust_analysis.check_empty_implementation
    end
    
    test "has certificate validation detection rules" do
      enhancement = TrustAllCerts.ast_enhancement()
      
      assert enhancement.ast_rules.certificate_analysis.check_certificate_validation
      assert enhancement.ast_rules.certificate_analysis.validation_methods
      assert enhancement.ast_rules.certificate_analysis.bypass_patterns
    end
    
    test "includes hostname verification analysis" do
      enhancement = TrustAllCerts.ast_enhancement()
      
      assert enhancement.ast_rules.hostname_analysis.check_hostname_verification
      assert enhancement.ast_rules.hostname_analysis.verifier_methods
      assert enhancement.ast_rules.hostname_analysis.bypass_indicators
    end
    
    test "includes SSL context analysis" do
      enhancement = TrustAllCerts.ast_enhancement()
      
      assert enhancement.ast_rules.ssl_analysis.check_ssl_context
      assert enhancement.ast_rules.ssl_analysis.ssl_methods
      assert enhancement.ast_rules.ssl_analysis.insecure_configurations
    end
    
    test "includes context-based filtering" do
      enhancement = TrustAllCerts.ast_enhancement()
      
      assert enhancement.context_rules.check_certificate_usage
      assert enhancement.context_rules.secure_trust_patterns
      assert enhancement.context_rules.insecure_trust_indicators
    end
    
    test "has proper confidence scoring" do
      enhancement = TrustAllCerts.ast_enhancement()
      
      adjustments = enhancement.confidence_rules.adjustments
      assert Map.has_key?(adjustments, "has_proper_validation")
      assert Map.has_key?(adjustments, "empty_trust_implementation")
      assert Map.has_key?(adjustments, "in_test_code")
      assert Map.has_key?(adjustments, "for_development_only")
    end
  end
end