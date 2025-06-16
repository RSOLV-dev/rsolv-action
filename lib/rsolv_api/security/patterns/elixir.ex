defmodule RsolvApi.Security.Patterns.Elixir do
  @moduledoc """
  Elixir security patterns for detecting vulnerabilities.
  
  This module contains 28 security patterns specifically designed for Elixir
  and Phoenix code. Each pattern includes detection rules, test cases, and 
  educational documentation.
  """
  
  alias RsolvApi.Security.Pattern
  alias RsolvApi.Security.Patterns.Elixir.SqlInjectionInterpolation
  alias RsolvApi.Security.Patterns.Elixir.SqlInjectionFragment
  alias RsolvApi.Security.Patterns.Elixir.CommandInjectionSystem
  alias RsolvApi.Security.Patterns.Elixir.XssRawHtml
  alias RsolvApi.Security.Patterns.Elixir.InsecureRandom
  alias RsolvApi.Security.Patterns.Elixir.UnsafeAtomCreation
  alias RsolvApi.Security.Patterns.Elixir.CodeInjectionEval
  alias RsolvApi.Security.Patterns.Elixir.DeserializationErlang
  alias RsolvApi.Security.Patterns.Elixir.PathTraversal
  alias RsolvApi.Security.Patterns.Elixir.SsrfHttpoison
  alias RsolvApi.Security.Patterns.Elixir.WeakCryptoMd5
  alias RsolvApi.Security.Patterns.Elixir.WeakCryptoSha1
  alias RsolvApi.Security.Patterns.Elixir.MissingCsrfProtection
  alias RsolvApi.Security.Patterns.Elixir.DebugModeEnabled
  alias RsolvApi.Security.Patterns.Elixir.UnsafeProcessSpawn
  alias RsolvApi.Security.Patterns.Elixir.AtomExhaustion
  alias RsolvApi.Security.Patterns.Elixir.EtsPublicTable
  alias RsolvApi.Security.Patterns.Elixir.MissingAuthPipeline
  alias RsolvApi.Security.Patterns.Elixir.UnsafeRedirect
  alias RsolvApi.Security.Patterns.Elixir.HardcodedSecrets
  alias RsolvApi.Security.Patterns.Elixir.UnsafeJsonDecode
  alias RsolvApi.Security.Patterns.Elixir.CookieSecurity
  alias RsolvApi.Security.Patterns.Elixir.UnsafeFileUpload
  alias RsolvApi.Security.Patterns.Elixir.InsufficientInputValidation
  alias RsolvApi.Security.Patterns.Elixir.ExposedErrorDetails
  alias RsolvApi.Security.Patterns.Elixir.UnsafeGenserverCalls
  alias RsolvApi.Security.Patterns.Elixir.MissingSslVerification
  alias RsolvApi.Security.Patterns.Elixir.WeakPasswordHashing
  
  @doc """
  Returns all Elixir security patterns.
  
  ## Examples
  
      iex> patterns = RsolvApi.Security.Patterns.Elixir.all()
      iex> length(patterns)
      28
      iex> Enum.all?(patterns, &match?(%Pattern{}, &1))
      true
  """
  def all do
    [
      sql_injection_interpolation(),
      sql_injection_fragment(),
      command_injection_system(),
      xss_raw_html(),
      insecure_random(),
      unsafe_atom_creation(),
      code_injection_eval(),
      deserialization_erlang(),
      path_traversal(),
      ssrf_httpoison(),
      weak_crypto_md5(),
      weak_crypto_sha1(),
      missing_csrf_protection(),
      debug_mode_enabled(),
      unsafe_process_spawn(),
      atom_exhaustion(),
      ets_public_table(),
      missing_auth_pipeline(),
      unsafe_redirect(),
      hardcoded_secrets(),
      unsafe_json_decode(),
      cookie_security(),
      unsafe_file_upload(),
      insufficient_input_validation(),
      exposed_error_details(),
      unsafe_genserver_calls(),
      missing_ssl_verification(),
      weak_password_hashing()
    ]
  end
  
  # Delegate to the SqlInjectionInterpolation module
  defdelegate sql_injection_interpolation(), to: SqlInjectionInterpolation, as: :pattern
  
  # Delegate to the SqlInjectionFragment module
  defdelegate sql_injection_fragment(), to: SqlInjectionFragment, as: :pattern
  
  # Delegate to the CommandInjectionSystem module  
  defdelegate command_injection_system(), to: CommandInjectionSystem, as: :pattern
  
  # Delegate to the XssRawHtml module
  defdelegate xss_raw_html(), to: XssRawHtml, as: :pattern
  
  # Delegate to the InsecureRandom module
  defdelegate insecure_random(), to: InsecureRandom, as: :pattern
  
  # Delegate to the UnsafeAtomCreation module
  defdelegate unsafe_atom_creation(), to: UnsafeAtomCreation, as: :pattern
  
  # Delegate to the CodeInjectionEval module
  defdelegate code_injection_eval(), to: CodeInjectionEval, as: :pattern
  
  # Delegate to the DeserializationErlang module
  defdelegate deserialization_erlang(), to: DeserializationErlang, as: :pattern
  
  # Delegate to the PathTraversal module
  defdelegate path_traversal(), to: PathTraversal, as: :pattern
  
  # Delegate to the SsrfHttpoison module
  defdelegate ssrf_httpoison(), to: SsrfHttpoison, as: :pattern
  
  
  # Delegate to the WeakCryptoMd5 module
  defdelegate weak_crypto_md5(), to: WeakCryptoMd5, as: :pattern
  
  # Delegate to the WeakCryptoSha1 module
  defdelegate weak_crypto_sha1(), to: WeakCryptoSha1, as: :pattern

  # Delegate to the MissingCsrfProtection module
  defdelegate missing_csrf_protection(), to: MissingCsrfProtection, as: :pattern

  # Delegate to the DebugModeEnabled module
  defdelegate debug_mode_enabled(), to: DebugModeEnabled, as: :pattern

  # Delegate to the UnsafeProcessSpawn module
  defdelegate unsafe_process_spawn(), to: UnsafeProcessSpawn, as: :pattern

  # Delegate to the AtomExhaustion module
  defdelegate atom_exhaustion(), to: AtomExhaustion, as: :pattern

  # Delegate to the EtsPublicTable module
  defdelegate ets_public_table(), to: EtsPublicTable, as: :pattern

  # Delegate to the MissingAuthPipeline module
  defdelegate missing_auth_pipeline(), to: MissingAuthPipeline, as: :pattern

  # Delegate to the UnsafeRedirect module
  defdelegate unsafe_redirect(), to: UnsafeRedirect, as: :pattern

  # Delegate to the HardcodedSecrets module
  defdelegate hardcoded_secrets(), to: HardcodedSecrets, as: :pattern

  # Delegate to the UnsafeJsonDecode module
  defdelegate unsafe_json_decode(), to: UnsafeJsonDecode, as: :pattern
  
  # Delegate to the CookieSecurity module
  defdelegate cookie_security(), to: CookieSecurity, as: :pattern
  
  # Delegate to the UnsafeFileUpload module
  defdelegate unsafe_file_upload(), to: UnsafeFileUpload, as: :pattern
  
  # Delegate to the InsufficientInputValidation module
  defdelegate insufficient_input_validation(), to: InsufficientInputValidation, as: :pattern
  
  # Delegate to the ExposedErrorDetails module
  defdelegate exposed_error_details(), to: ExposedErrorDetails, as: :pattern
  
  # Delegate to the UnsafeGenserverCalls module
  defdelegate unsafe_genserver_calls(), to: UnsafeGenserverCalls, as: :pattern
  
  # Delegate to the MissingSslVerification module
  defdelegate missing_ssl_verification(), to: MissingSslVerification, as: :pattern
  
  # Delegate to the WeakPasswordHashing module
  defdelegate weak_password_hashing(), to: WeakPasswordHashing, as: :pattern
end