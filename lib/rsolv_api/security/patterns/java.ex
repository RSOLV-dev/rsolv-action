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
  alias RsolvApi.Security.Patterns.Java.XxeDocumentbuilder
  alias RsolvApi.Security.Patterns.Java.XxeSaxparser
  alias RsolvApi.Security.Patterns.Java.LdapInjection
  alias RsolvApi.Security.Patterns.Java.HardcodedPassword
  alias RsolvApi.Security.Patterns.Java.WeakRandom
  
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
  
  # Delegate to the XxeDocumentbuilder module
  defdelegate xxe_documentbuilder(), to: XxeDocumentbuilder, as: :pattern
  
  # Delegate to the XxeSaxparser module
  defdelegate xxe_saxparser(), to: XxeSaxparser, as: :pattern
  
  # Delegate to the LdapInjection module
  defdelegate ldap_injection(), to: LdapInjection, as: :pattern
  
  # Delegate to the HardcodedPassword module
  defdelegate hardcoded_password(), to: HardcodedPassword, as: :pattern
  
  # Delegate to the WeakRandom module
  defdelegate weak_random(), to: WeakRandom, as: :pattern
  
  
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