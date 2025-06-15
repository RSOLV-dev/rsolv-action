defmodule RsolvApi.Security.Patterns.Java do
  @moduledoc """
  Java security patterns for detecting vulnerabilities.
  
  This module contains 17 security patterns specifically designed for Java
  code. Each pattern includes detection rules, test cases, and educational
  documentation.
  """
  
  alias RsolvApi.Security.Pattern
  alias RsolvApi.Security.Patterns.Java.SqlInjectionStatement
  alias RsolvApi.Security.Patterns.Java.SqlInjectionStringFormat
  alias RsolvApi.Security.Patterns.Java.UnsafeDeserialization
  alias RsolvApi.Security.Patterns.Java.XpathInjection
  alias RsolvApi.Security.Patterns.Java.CommandInjectionRuntimeExec
  alias RsolvApi.Security.Patterns.Java.CommandInjectionProcessbuilder
  alias RsolvApi.Security.Patterns.Java.PathTraversalFile
  alias RsolvApi.Security.Patterns.Java.PathTraversalFileinputstream
  alias RsolvApi.Security.Patterns.Java.WeakHashMd5
  alias RsolvApi.Security.Patterns.Java.WeakHashSha1
  alias RsolvApi.Security.Patterns.Java.WeakCipherDes
  
  @doc """
  Returns all Java security patterns.
  
  ## Examples
  
      iex> patterns = RsolvApi.Security.Patterns.Java.all()
      iex> length(patterns)
      17
      iex> Enum.all?(patterns, &match?(%Pattern{}, &1))
      true
  """
  def all do
    [
      sql_injection_statement(),
      sql_injection_string_format(),
      unsafe_deserialization(),
      xpath_injection(),
      command_injection_runtime_exec(),
      command_injection_processbuilder(),
      path_traversal_file(),
      path_traversal_fileinputstream(),
      weak_hash_md5(),
      weak_hash_sha1(),
      weak_cipher_des(),
      xxe_documentbuilder(),
      xxe_saxparser(),
      ldap_injection(),
      hardcoded_password(),
      weak_random(),
      trust_all_certs()
    ]
  end
  
  # Delegate to the SqlInjectionStatement module
  defdelegate sql_injection_statement(), to: SqlInjectionStatement, as: :pattern
  
  # Delegate to the SqlInjectionStringFormat module
  defdelegate sql_injection_string_format(), to: SqlInjectionStringFormat, as: :pattern
  
  # Delegate to the UnsafeDeserialization module
  defdelegate unsafe_deserialization(), to: UnsafeDeserialization, as: :pattern
  
  # Delegate to the XpathInjection module
  defdelegate xpath_injection(), to: XpathInjection, as: :pattern
  
  # Delegate to the CommandInjectionRuntimeExec module
  defdelegate command_injection_runtime_exec(), to: CommandInjectionRuntimeExec, as: :pattern
  
  # Delegate to the CommandInjectionProcessbuilder module
  defdelegate command_injection_processbuilder(), to: CommandInjectionProcessbuilder, as: :pattern
  
  # Delegate to the PathTraversalFile module
  defdelegate path_traversal_file(), to: PathTraversalFile, as: :pattern
  
  # Delegate to the PathTraversalFileinputstream module
  defdelegate path_traversal_fileinputstream(), to: PathTraversalFileinputstream, as: :pattern
  
  # Delegate to the WeakHashMd5 module
  defdelegate weak_hash_md5(), to: WeakHashMd5, as: :pattern
  
  # Delegate to the WeakHashSha1 module
  defdelegate weak_hash_sha1(), to: WeakHashSha1, as: :pattern
  
  # Delegate to the WeakCipherDes module
  defdelegate weak_cipher_des(), to: WeakCipherDes, as: :pattern
  
  
  @doc """
  XXE via DocumentBuilder pattern.
  
  Detects XXE vulnerabilities in DocumentBuilder.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Java.xxe_documentbuilder()
      iex> vulnerable = "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance(); DocumentBuilder db = dbf.newDocumentBuilder();"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def xxe_documentbuilder do
    %Pattern{
      id: "java-xxe-documentbuilder",
      name: "XXE via DocumentBuilder",
      description: "DocumentBuilder without secure processing",
      type: :xxe,
      severity: :high,
      languages: ["java"],
      regex: ~r/DocumentBuilderFactory.*\.newDocumentBuilder\(\)(?![\s\S]*setFeature.*XMLConstants\.FEATURE_SECURE_PROCESSING)/,
      default_tier: :protected,
      cwe_id: "CWE-611",
      owasp_category: "A05:2021",
      recommendation: "Enable secure processing and disable external entity processing",
      test_cases: %{
        vulnerable: [
          ~S|DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();|
        ],
        safe: [
          ~S|DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
DocumentBuilder db = dbf.newDocumentBuilder();|
        ]
      }
    }
  end
  
  @doc """
  XXE via SAXParser pattern.
  
  Detects XXE vulnerabilities in SAXParser.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Java.xxe_saxparser()
      iex> vulnerable = "SAXParserFactory spf = SAXParserFactory.newInstance(); SAXParser parser = spf.newSAXParser();"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def xxe_saxparser do
    %Pattern{
      id: "java-xxe-saxparser",
      name: "XXE via SAXParser",
      description: "SAXParser without secure processing",
      type: :xxe,
      severity: :high,
      languages: ["java"],
      regex: ~r/SAXParserFactory.*\.newSAXParser\(\)(?![\s\S]*setFeature.*XMLConstants\.FEATURE_SECURE_PROCESSING)/,
      default_tier: :protected,
      cwe_id: "CWE-611",
      owasp_category: "A05:2021",
      recommendation: "Enable secure processing and disable external entity processing",
      test_cases: %{
        vulnerable: [
          ~S|SAXParserFactory spf = SAXParserFactory.newInstance();
SAXParser parser = spf.newSAXParser();|
        ],
        safe: [
          ~S|SAXParserFactory spf = SAXParserFactory.newInstance();
spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
SAXParser parser = spf.newSAXParser();|
        ]
      }
    }
  end
  
  @doc """
  LDAP Injection pattern.
  
  Detects LDAP injection vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Java.ldap_injection()
      iex> vulnerable = ~S|ctx.search("cn=" + username + ",ou=users", filter, controls);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def ldap_injection do
    %Pattern{
      id: "java-ldap-injection",
      name: "LDAP Injection",
      description: "String concatenation in LDAP search",
      type: :ldap_injection,
      severity: :high,
      languages: ["java"],
      regex: ~r/\.search\s*\(\s*.*\+.*,/,
      default_tier: :protected,
      cwe_id: "CWE-90",
      owasp_category: "A03:2021",
      recommendation: "Use parameterized LDAP queries and validate input",
      test_cases: %{
        vulnerable: [
          ~S|ctx.search("cn=" + username + ",ou=users", filter, controls);|,
          ~S|ctx.search("ou=users", "(uid=" + uid + ")", controls);|
        ],
        safe: [
          ~S|// Escape special LDAP characters
String escapedUsername = LdapEncoder.filterEncode(username);
ctx.search("cn=" + escapedUsername + ",ou=users", filter, controls);|,
          ~S|// Use SearchControls with proper filtering
SearchControls searchControls = new SearchControls();
searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
String filter = "(&(objectClass=user)(uid={0}))";
ctx.search("ou=users", filter, new Object[]{uid}, searchControls);|
        ]
      }
    }
  end
  
  @doc """
  Hardcoded Password pattern.
  
  Detects hardcoded credentials in source code.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Java.hardcoded_password()
      iex> vulnerable = ~S|String password = "admin123";|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def hardcoded_password do
    %Pattern{
      id: "java-hardcoded-password",
      name: "Hardcoded Credentials",
      description: "Password in source code",
      type: :hardcoded_secret,
      severity: :high,
      languages: ["java"],
      regex: ~r/(?:password|pwd|passwd)\s*=\s*["'][^"']{6,}["']/i,
      default_tier: :public,
      cwe_id: "CWE-798",
      owasp_category: "A07:2021",
      recommendation: "Use environment variables or secure configuration management",
      test_cases: %{
        vulnerable: [
          ~S|String password = "admin123";|,
          ~S|private static final String PASSWORD = "secretpass";|,
          ~S|conn = DriverManager.getConnection(url, "user", "passwd123");|
        ],
        safe: [
          ~S|String password = System.getenv("DB_PASSWORD");|,
          ~S|String password = config.getString("database.password");|,
          ~S|// Use a secure credential management system
String password = credentialManager.getPassword("database");|
        ]
      }
    }
  end
  
  @doc """
  Weak Random Number Generation pattern.
  
  Detects usage of java.util.Random for security purposes.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Java.weak_random()
      iex> vulnerable = ~S|Random rand = new Random();|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def weak_random do
    %Pattern{
      id: "java-weak-random",
      name: "Weak Random Number Generation",
      description: "java.util.Random is not cryptographically secure",
      type: :insecure_random,
      severity: :medium,
      languages: ["java"],
      regex: ~r/new\s+Random\s*\(\)|Math\.random\s*\(\)/,
      default_tier: :public,
      cwe_id: "CWE-338",
      owasp_category: "A02:2021",
      recommendation: "Use SecureRandom for security-sensitive random values",
      test_cases: %{
        vulnerable: [
          ~S|Random rand = new Random();
int token = rand.nextInt(1000000);|,
          ~S|double randomValue = Math.random();|
        ],
        safe: [
          ~S|SecureRandom secureRandom = new SecureRandom();
byte[] token = new byte[16];
secureRandom.nextBytes(token);|,
          ~S|SecureRandom random = SecureRandom.getInstanceStrong();|
        ]
      }
    }
  end
  
  @doc """
  Trust All Certificates pattern.
  
  Detects TrustManager that accepts all certificates.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Java.trust_all_certs()
      iex> vulnerable = "new X509TrustManager() { public void checkClientTrusted(X509Certificate[] chain, String authType) {} }"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def trust_all_certs do
    %Pattern{
      id: "java-trust-all-certs",
      name: "Trust All Certificates",
      description: "TrustManager that accepts all certificates",
      type: :authentication,
      severity: :critical,
      languages: ["java"],
      regex: ~r/TrustManager.*\{\s*public\s+void\s+checkClientTrusted.*\{\s*\}/,
      default_tier: :protected,
      cwe_id: "CWE-295",
      owasp_category: "A07:2021",
      recommendation: "Implement proper certificate validation",
      test_cases: %{
        vulnerable: [
          ~S|TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }
};|
        ],
        safe: [
          ~S|// Use default TrustManager
SSLContext sslContext = SSLContext.getInstance("TLS");
sslContext.init(null, null, new SecureRandom());|,
          ~S|// Or implement proper certificate validation
TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
tmf.init((KeyStore) null);
TrustManager[] trustManagers = tmf.getTrustManagers();|
        ]
      }
    }
  end
end