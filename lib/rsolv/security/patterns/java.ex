defmodule Rsolv.Security.Patterns.Java do
  @moduledoc """
  Java security patterns for detecting vulnerabilities.
  
  This module contains 17 security patterns specifically designed for Java
  code. Each pattern includes detection rules, test cases, and educational
  documentation.
  """
  
  alias Rsolv.Security.Patterns.Java.SqlInjectionStatement
  alias Rsolv.Security.Patterns.Java.SqlInjectionStringFormat
  alias Rsolv.Security.Patterns.Java.UnsafeDeserialization
  alias Rsolv.Security.Patterns.Java.XpathInjection
  alias Rsolv.Security.Patterns.Java.CommandInjectionRuntimeExec
  alias Rsolv.Security.Patterns.Java.CommandInjectionProcessbuilder
  alias Rsolv.Security.Patterns.Java.PathTraversalFile
  alias Rsolv.Security.Patterns.Java.PathTraversalFileinputstream
  alias Rsolv.Security.Patterns.Java.WeakHashMd5
  alias Rsolv.Security.Patterns.Java.WeakHashSha1
  alias Rsolv.Security.Patterns.Java.WeakCipherDes
  alias Rsolv.Security.Patterns.Java.XxeDocumentbuilder
  alias Rsolv.Security.Patterns.Java.XxeSaxparser
  alias Rsolv.Security.Patterns.Java.LdapInjection
  alias Rsolv.Security.Patterns.Java.HardcodedPassword
  alias Rsolv.Security.Patterns.Java.WeakRandom
  alias Rsolv.Security.Patterns.Java.TrustAllCerts
  
  @doc """
  Returns all Java security patterns.
  
  ## Examples
  
      iex> patterns = Rsolv.Security.Patterns.Java.all()
      iex> length(patterns)
      17
      iex> Enum.all?(patterns, &match?(%Rsolv.Security.Pattern{}, &1))
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
  
  # Delegate to the TrustAllCerts module
  defdelegate trust_all_certs(), to: TrustAllCerts, as: :pattern
  
  
end
