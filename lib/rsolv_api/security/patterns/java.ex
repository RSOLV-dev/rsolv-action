defmodule RsolvApi.Security.Patterns.Java do
  @moduledoc """
  Java security patterns for detecting vulnerabilities.
  
  This module contains 17 security patterns specifically designed for Java
  code. Each pattern includes detection rules, test cases, and educational
  documentation.
  """
  
  alias RsolvApi.Security.Pattern
  
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
  
  @doc """
  SQL Injection via Statement pattern.
  
  Detects SQL injection through Statement with string concatenation.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Java.sql_injection_statement()
      iex> pattern.id
      "java-sql-injection-statement"
      iex> pattern.severity
      :high
  """
  def sql_injection_statement do
    %Pattern{
      id: "java-sql-injection-statement",
      name: "SQL Injection via Statement",
      description: "String concatenation in executeQuery() leads to SQL injection",
      type: :sql_injection,
      severity: :high,
      languages: ["java"],
      regex: ~r/Statement\s+\w+\s*=.*\.createStatement\(\)[\s\S]*?\.executeQuery\s*\(\s*.*\+/,
      default_tier: :protected,
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation: "Use PreparedStatement with parameterized queries",
      test_cases: %{
        vulnerable: [
          ~S|Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);|,
          ~S|stmt.executeQuery("SELECT * FROM products WHERE name = '" + productName + "'");|
        ],
        safe: [
          ~S|PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
pstmt.setInt(1, userId);
ResultSet rs = pstmt.executeQuery();|,
          ~S|PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM products WHERE name = ?");
pstmt.setString(1, productName);|
        ]
      }
    }
  end
  
  @doc """
  SQL Injection via String.format pattern.
  
  Detects SQL injection through String.format() in queries.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Java.sql_injection_string_format()
      iex> vulnerable = ~S|executeQuery(String.format("SELECT * FROM users WHERE id = %s", userId))|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def sql_injection_string_format do
    %Pattern{
      id: "java-sql-injection-string-format",
      name: "SQL Injection via String.format",
      description: "String.format() in SQL queries can lead to injection",
      type: :sql_injection,
      severity: :high,
      languages: ["java"],
      regex: ~r/executeQuery\s*\(\s*String\.format\s*\(/,
      default_tier: :protected,
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation: "Use PreparedStatement with setString(), setInt(), etc.",
      test_cases: %{
        vulnerable: [
          ~S|executeQuery(String.format("SELECT * FROM users WHERE id = %s", userId))|,
          ~S|stmt.executeQuery(String.format("DELETE FROM posts WHERE author = '%s'", author))|
        ],
        safe: [
          ~S|PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
pstmt.setString(1, userId);|,
          ~S|pstmt.setString(1, author);
pstmt.executeUpdate();|
        ]
      }
    }
  end
  
  @doc """
  Unsafe Deserialization pattern.
  
  Detects ObjectInputStream.readObject() which can execute arbitrary code.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Java.unsafe_deserialization()
      iex> vulnerable = "ObjectInputStream ois = new ObjectInputStream(input); Object obj = ois.readObject();"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def unsafe_deserialization do
    %Pattern{
      id: "java-unsafe-deserialization",
      name: "Insecure Deserialization",
      description: "ObjectInputStream.readObject() can execute arbitrary code",
      type: :deserialization,
      severity: :critical,
      languages: ["java"],
      regex: ~r/ObjectInputStream.*\.readObject\s*\(\)/,
      default_tier: :protected,
      cwe_id: "CWE-502",
      owasp_category: "A08:2021",
      recommendation: "Implement custom readObject() with validation or use safe serialization libraries",
      test_cases: %{
        vulnerable: [
          ~S|ObjectInputStream ois = new ObjectInputStream(input);
Object obj = ois.readObject();|,
          ~S|return new ObjectInputStream(fileInputStream).readObject();|
        ],
        safe: [
          ~S|// Use JSON serialization instead
ObjectMapper mapper = new ObjectMapper();
User user = mapper.readValue(jsonString, User.class);|,
          ~S|// Implement ObjectInputFilter for validation
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter("maxdepth=5;maxarray=100");|
        ]
      }
    }
  end
  
  @doc """
  XPath Injection pattern.
  
  Detects XPath injection vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Java.xpath_injection()
      iex> vulnerable = "XPath xpath = XPathFactory.newInstance().newXPath(); xpath.evaluate(\"//user[name='\" + username + \"']\", doc);"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def xpath_injection do
    %Pattern{
      id: "java-xpath-injection",
      name: "XPath Injection",
      description: "String concatenation in XPath expressions",
      type: :xpath_injection,
      severity: :high,
      languages: ["java"],
      regex: ~r/XPath.*\.compile\s*\(\s*.*\+|XPath.*\.evaluate\s*\(\s*.*\+/,
      default_tier: :protected,
      cwe_id: "CWE-643",
      owasp_category: "A03:2021",
      recommendation: "Use parameterized XPath expressions or validate input",
      test_cases: %{
        vulnerable: [
          ~S|XPath xpath = XPathFactory.newInstance().newXPath();
xpath.evaluate("//user[name='" + username + "']", doc);|,
          ~S|xpath.compile("//product[@id='" + productId + "']");|
        ],
        safe: [
          ~S|// Use XPath variables
XPath xpath = XPathFactory.newInstance().newXPath();
xpath.setXPathVariableResolver(resolver);
xpath.evaluate("//user[name=$username]", doc);|,
          ~S|// Validate input
String safeUsername = validateUsername(username);
xpath.evaluate("//user[name='" + safeUsername + "']", doc);|
        ]
      }
    }
  end
  
  @doc """
  Command Injection via Runtime.exec pattern.
  
  Detects command injection through Runtime.exec().
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Java.command_injection_runtime_exec()
      iex> vulnerable = ~S|Runtime.getRuntime().exec("ping " + hostname);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def command_injection_runtime_exec do
    %Pattern{
      id: "java-command-injection-runtime-exec",
      name: "Command Injection via Runtime.exec",
      description: "String concatenation in Runtime.exec() can lead to command injection",
      type: :command_injection,
      severity: :critical,
      languages: ["java"],
      regex: ~r/Runtime\.getRuntime\(\)\.exec\s*\(\s*.*\+/,
      default_tier: :protected,
      cwe_id: "CWE-78",
      owasp_category: "A03:2021",
      recommendation: "Use ProcessBuilder with array of arguments and validate input",
      test_cases: %{
        vulnerable: [
          ~S|Runtime.getRuntime().exec("ping " + hostname);|,
          ~S|Runtime.getRuntime().exec("cmd /c dir " + directory);|
        ],
        safe: [
          ~S|ProcessBuilder pb = new ProcessBuilder("ping", hostname);
Process p = pb.start();|,
          ~S|String[] cmd = {"ping", hostname};
Runtime.getRuntime().exec(cmd);|
        ]
      }
    }
  end
  
  @doc """
  Command Injection via ProcessBuilder pattern.
  
  Detects command injection through ProcessBuilder.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Java.command_injection_processbuilder()
      iex> vulnerable = "ProcessBuilder pb = new ProcessBuilder(); pb.command(\"sh -c \" + userCommand);"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def command_injection_processbuilder do
    %Pattern{
      id: "java-command-injection-processbuilder",
      name: "Command Injection via ProcessBuilder",
      description: "String concatenation in ProcessBuilder.command() can lead to command injection",
      type: :command_injection,
      severity: :high,
      languages: ["java"],
      regex: ~r/ProcessBuilder.*\.command\s*\(\s*.*\+/,
      default_tier: :protected,
      cwe_id: "CWE-78",
      owasp_category: "A03:2021",
      recommendation: "Use ProcessBuilder with separate arguments and validate input",
      test_cases: %{
        vulnerable: [
          ~S|ProcessBuilder pb = new ProcessBuilder();
pb.command("sh -c " + userCommand);|,
          ~S|new ProcessBuilder().command("cmd /c " + command);|
        ],
        safe: [
          ~S|ProcessBuilder pb = new ProcessBuilder("echo", message);|,
          ~S|List<String> command = Arrays.asList("grep", pattern, "file.txt");
ProcessBuilder pb = new ProcessBuilder(command);|
        ]
      }
    }
  end
  
  @doc """
  Path Traversal via File constructor pattern.
  
  Detects path traversal vulnerabilities in File operations.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Java.path_traversal_file()
      iex> vulnerable = ~S|File file = new File(uploadDir + "/" + filename);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def path_traversal_file do
    %Pattern{
      id: "java-path-traversal-file",
      name: "Path Traversal via File",
      description: "Unsanitized file paths in File constructor",
      type: :path_traversal,
      severity: :medium,
      languages: ["java"],
      regex: ~r/new\s+File\s*\(\s*.*\+/,
      default_tier: :protected,
      cwe_id: "CWE-22",
      owasp_category: "A01:2021",
      recommendation: "Validate and sanitize file paths, use Paths.get() with validation",
      test_cases: %{
        vulnerable: [
          ~S|File file = new File(uploadDir + "/" + filename);|,
          ~S|new File(baseDir + File.separator + userPath);|
        ],
        safe: [
          ~S|Path path = Paths.get(uploadDir, filename).normalize();
if (path.startsWith(uploadDir)) {
    File file = path.toFile();
}|,
          ~S|String safeFilename = Paths.get(filename).getFileName().toString();
File file = new File(uploadDir, safeFilename);|
        ]
      }
    }
  end
  
  @doc """
  Path Traversal via FileInputStream pattern.
  
  Detects path traversal in FileInputStream operations.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Java.path_traversal_fileinputstream()
      iex> vulnerable = ~S|FileInputStream fis = new FileInputStream(baseDir + filename);|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def path_traversal_fileinputstream do
    %Pattern{
      id: "java-path-traversal-fileinputstream",
      name: "Path Traversal via FileInputStream",
      description: "Unsanitized file paths in FileInputStream",
      type: :path_traversal,
      severity: :medium,
      languages: ["java"],
      regex: ~r/new\s+FileInputStream\s*\(\s*.*\+/,
      default_tier: :protected,
      cwe_id: "CWE-22",
      owasp_category: "A01:2021",
      recommendation: "Validate file paths and use Files.newInputStream() with proper validation",
      test_cases: %{
        vulnerable: [
          ~S|FileInputStream fis = new FileInputStream(baseDir + filename);|,
          ~S|new FileInputStream("/uploads/" + userFile);|
        ],
        safe: [
          ~S|Path path = Paths.get(baseDir, filename).normalize();
if (path.startsWith(baseDir)) {
    InputStream is = Files.newInputStream(path);
}|,
          ~S|// Validate filename contains no path separators
if (!filename.contains("..") && !filename.contains("/")) {
    FileInputStream fis = new FileInputStream(new File(baseDir, filename));
}|
        ]
      }
    }
  end
  
  @doc """
  Weak Cryptography - MD5 pattern.
  
  Detects usage of MD5 for cryptographic purposes.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Java.weak_hash_md5()
      iex> vulnerable = ~S|MessageDigest md = MessageDigest.getInstance("MD5");|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def weak_hash_md5 do
    %Pattern{
      id: "java-weak-hash-md5",
      name: "Weak Cryptography - MD5",
      description: "MD5 is cryptographically broken",
      type: :weak_crypto,
      severity: :medium,
      languages: ["java"],
      regex: ~r/MessageDigest\.getInstance\s*\(\s*["']MD5["']\s*\)/,
      default_tier: :public,
      cwe_id: "CWE-327",
      owasp_category: "A02:2021",
      recommendation: "Use SHA-256 or SHA-3 for cryptographic hashing",
      test_cases: %{
        vulnerable: [
          ~S|MessageDigest md = MessageDigest.getInstance("MD5");|,
          ~S|MessageDigest.getInstance("MD5").digest(password.getBytes());|
        ],
        safe: [
          ~S|MessageDigest md = MessageDigest.getInstance("SHA-256");|,
          ~S|// For passwords, use proper password hashing
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
String hashedPassword = encoder.encode(password);|
        ]
      }
    }
  end
  
  @doc """
  Weak Cryptography - SHA1 pattern.
  
  Detects usage of SHA1 for security purposes.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Java.weak_hash_sha1()
      iex> vulnerable = ~S|MessageDigest md = MessageDigest.getInstance("SHA-1");|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def weak_hash_sha1 do
    %Pattern{
      id: "java-weak-hash-sha1",
      name: "Weak Cryptography - SHA1",
      description: "SHA-1 is deprecated for security purposes",
      type: :weak_crypto,
      severity: :medium,
      languages: ["java"],
      regex: ~r/MessageDigest\.getInstance\s*\(\s*["']SHA-1["']\s*\)/,
      default_tier: :public,
      cwe_id: "CWE-327",
      owasp_category: "A02:2021",
      recommendation: "Use SHA-256 or SHA-3 for cryptographic hashing",
      test_cases: %{
        vulnerable: [
          ~S|MessageDigest md = MessageDigest.getInstance("SHA-1");|,
          ~S|MessageDigest.getInstance("SHA-1").digest(data);|
        ],
        safe: [
          ~S|MessageDigest md = MessageDigest.getInstance("SHA-256");|,
          ~S|MessageDigest md = MessageDigest.getInstance("SHA3-256");|
        ]
      }
    }
  end
  
  @doc """
  Weak Cipher - DES pattern.
  
  Detects usage of DES encryption.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Java.weak_cipher_des()
      iex> vulnerable = ~S|Cipher cipher = Cipher.getInstance("DES");|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
  """
  def weak_cipher_des do
    %Pattern{
      id: "java-weak-cipher-des",
      name: "Weak Cryptography - DES",
      description: "DES encryption is insecure",
      type: :weak_crypto,
      severity: :high,
      languages: ["java"],
      regex: ~r/Cipher\.getInstance\s*\(\s*["']DES/,
      default_tier: :public,
      cwe_id: "CWE-327",
      owasp_category: "A02:2021",
      recommendation: "Use AES with appropriate key sizes (AES-256)",
      test_cases: %{
        vulnerable: [
          ~S|Cipher cipher = Cipher.getInstance("DES");|,
          ~S|Cipher cipher = Cipher.getInstance("DESede");|
        ],
        safe: [
          ~S|Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");|,
          ~S|Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");|
        ]
      }
    }
  end
  
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