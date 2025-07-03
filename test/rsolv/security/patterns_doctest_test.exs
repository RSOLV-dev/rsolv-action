defmodule Rsolv.Security.PatternsDoctestTest do
  use ExUnit.Case, async: true
  
  alias Rsolv.Security.Pattern

  # Test JavaScript patterns
  doctest Rsolv.Security.Patterns.Javascript
  
  # Test Python patterns
  doctest Rsolv.Security.Patterns.Python
  doctest Rsolv.Security.Patterns.Python.UnsafePickle
  doctest Rsolv.Security.Patterns.Python.UnsafeEval
  doctest Rsolv.Security.Patterns.Python.SqlInjectionFormat
  doctest Rsolv.Security.Patterns.Python.SqlInjectionFstring
  doctest Rsolv.Security.Patterns.Python.SqlInjectionConcat
  doctest Rsolv.Security.Patterns.Python.CommandInjectionOsSystem
  doctest Rsolv.Security.Patterns.Python.CommandInjectionSubprocessShell
  doctest Rsolv.Security.Patterns.Python.PathTraversalOpen
  doctest Rsolv.Security.Patterns.Python.WeakHashMd5
  doctest Rsolv.Security.Patterns.Python.WeakHashSha1
  doctest Rsolv.Security.Patterns.Python.DebugTrue
  doctest Rsolv.Security.Patterns.Python.UnsafeYamlLoad
  
  # Test Java patterns
  doctest Rsolv.Security.Patterns.Java
  doctest Rsolv.Security.Patterns.Java.PathTraversalFileinputstream
  doctest Rsolv.Security.Patterns.Java.WeakHashMd5
  doctest Rsolv.Security.Patterns.Java.WeakHashSha1
  doctest Rsolv.Security.Patterns.Java.WeakCipherDes
  doctest Rsolv.Security.Patterns.Java.XxeDocumentbuilder
  doctest Rsolv.Security.Patterns.Java.XxeSaxparser
  doctest Rsolv.Security.Patterns.Java.LdapInjection
  doctest Rsolv.Security.Patterns.Java.HardcodedPassword
  doctest Rsolv.Security.Patterns.Java.WeakRandom
  doctest Rsolv.Security.Patterns.Java.TrustAllCerts
  
  # Test Elixir patterns
  doctest Rsolv.Security.Patterns.Elixir
  doctest Rsolv.Security.Patterns.Elixir.SqlInjectionInterpolation
  doctest Rsolv.Security.Patterns.Elixir.SqlInjectionFragment
  doctest Rsolv.Security.Patterns.Elixir.CommandInjectionSystem
  doctest Rsolv.Security.Patterns.Elixir.XssRawHtml
  doctest Rsolv.Security.Patterns.Elixir.InsecureRandom
  doctest Rsolv.Security.Patterns.Elixir.UnsafeAtomCreation
  doctest Rsolv.Security.Patterns.Elixir.CodeInjectionEval
  doctest Rsolv.Security.Patterns.Elixir.DeserializationErlang
  doctest Rsolv.Security.Patterns.Elixir.PathTraversal
  doctest Rsolv.Security.Patterns.Elixir.SsrfHttpoison
  doctest Rsolv.Security.Patterns.Elixir.WeakCryptoMd5
  doctest Rsolv.Security.Patterns.Elixir.WeakCryptoSha1
  doctest Rsolv.Security.Patterns.Elixir.MissingCsrfProtection
  doctest Rsolv.Security.Patterns.Elixir.DebugModeEnabled
  doctest Rsolv.Security.Patterns.Elixir.UnsafeProcessSpawn
  doctest Rsolv.Security.Patterns.Elixir.AtomExhaustion
  doctest Rsolv.Security.Patterns.Elixir.EtsPublicTable
  doctest Rsolv.Security.Patterns.Elixir.MissingAuthPipeline
  doctest Rsolv.Security.Patterns.Elixir.UnsafeRedirect
  doctest Rsolv.Security.Patterns.Elixir.HardcodedSecrets
  doctest Rsolv.Security.Patterns.Elixir.UnsafeJsonDecode
  doctest Rsolv.Security.Patterns.Elixir.CookieSecurity
  doctest Rsolv.Security.Patterns.Elixir.UnsafeFileUpload
  doctest Rsolv.Security.Patterns.Elixir.InsufficientInputValidation
  doctest Rsolv.Security.Patterns.Elixir.ExposedErrorDetails
  doctest Rsolv.Security.Patterns.Elixir.UnsafeGenserverCalls
  doctest Rsolv.Security.Patterns.Elixir.MissingSslVerification
  doctest Rsolv.Security.Patterns.Elixir.WeakPasswordHashing
  
  # Test PHP patterns
  doctest Rsolv.Security.Patterns.Php
  doctest Rsolv.Security.Patterns.Php.SqlInjectionConcat
  doctest Rsolv.Security.Patterns.Php.SqlInjectionInterpolation
  doctest Rsolv.Security.Patterns.Php.CommandInjection
  doctest Rsolv.Security.Patterns.Php.XssEcho
  
  # Test CVE patterns
  doctest Rsolv.Security.Patterns.Cve
  
  # Test Ruby patterns
  doctest Rsolv.Security.Patterns.Ruby
  doctest Rsolv.Security.Patterns.Ruby.MissingAuthentication
  doctest Rsolv.Security.Patterns.Ruby.MassAssignment
  doctest Rsolv.Security.Patterns.Ruby.HardcodedSecrets
  doctest Rsolv.Security.Patterns.Ruby.SqlInjectionInterpolation
  doctest Rsolv.Security.Patterns.Ruby.CommandInjection
  doctest Rsolv.Security.Patterns.Ruby.XpathInjection
  doctest Rsolv.Security.Patterns.Ruby.LdapInjection
  doctest Rsolv.Security.Patterns.Ruby.WeakRandom
  doctest Rsolv.Security.Patterns.Ruby.DebugModeEnabled
  doctest Rsolv.Security.Patterns.Ruby.EvalUsage
  doctest Rsolv.Security.Patterns.Ruby.WeakPasswordStorage
  doctest Rsolv.Security.Patterns.Ruby.UnsafeDeserializationMarshal
  doctest Rsolv.Security.Patterns.Ruby.UnsafeYaml
  doctest Rsolv.Security.Patterns.Ruby.InsufficientLogging
  doctest Rsolv.Security.Patterns.Ruby.SsrfOpenUri
  doctest Rsolv.Security.Patterns.Ruby.XssErbRaw
  doctest Rsolv.Security.Patterns.Ruby.PathTraversal
  doctest Rsolv.Security.Patterns.Ruby.OpenRedirect
  doctest Rsolv.Security.Patterns.Ruby.InsecureCookie
end