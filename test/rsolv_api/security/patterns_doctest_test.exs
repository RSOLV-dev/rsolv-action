defmodule RsolvApi.Security.PatternsDoctestTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Pattern

  # Test JavaScript patterns
  doctest RsolvApi.Security.Patterns.Javascript
  
  # Test Python patterns
  doctest RsolvApi.Security.Patterns.Python
  doctest RsolvApi.Security.Patterns.Python.UnsafePickle
  doctest RsolvApi.Security.Patterns.Python.UnsafeEval
  doctest RsolvApi.Security.Patterns.Python.SqlInjectionFormat
  doctest RsolvApi.Security.Patterns.Python.SqlInjectionFstring
  doctest RsolvApi.Security.Patterns.Python.SqlInjectionConcat
  doctest RsolvApi.Security.Patterns.Python.CommandInjectionOsSystem
  doctest RsolvApi.Security.Patterns.Python.CommandInjectionSubprocessShell
  doctest RsolvApi.Security.Patterns.Python.PathTraversalOpen
  doctest RsolvApi.Security.Patterns.Python.WeakHashMd5
  doctest RsolvApi.Security.Patterns.Python.WeakHashSha1
  doctest RsolvApi.Security.Patterns.Python.DebugTrue
  doctest RsolvApi.Security.Patterns.Python.UnsafeYamlLoad
  
  # Test Java patterns
  doctest RsolvApi.Security.Patterns.Java
  doctest RsolvApi.Security.Patterns.Java.PathTraversalFileinputstream
  doctest RsolvApi.Security.Patterns.Java.WeakHashMd5
  doctest RsolvApi.Security.Patterns.Java.WeakHashSha1
  doctest RsolvApi.Security.Patterns.Java.WeakCipherDes
  doctest RsolvApi.Security.Patterns.Java.XxeDocumentbuilder
  doctest RsolvApi.Security.Patterns.Java.XxeSaxparser
  doctest RsolvApi.Security.Patterns.Java.LdapInjection
  doctest RsolvApi.Security.Patterns.Java.HardcodedPassword
  doctest RsolvApi.Security.Patterns.Java.WeakRandom
  doctest RsolvApi.Security.Patterns.Java.TrustAllCerts
  
  # Test Elixir patterns
  doctest RsolvApi.Security.Patterns.Elixir
  doctest RsolvApi.Security.Patterns.Elixir.SqlInjectionInterpolation
  doctest RsolvApi.Security.Patterns.Elixir.SqlInjectionFragment
  doctest RsolvApi.Security.Patterns.Elixir.CommandInjectionSystem
  doctest RsolvApi.Security.Patterns.Elixir.XssRawHtml
  
  # Test PHP patterns
  doctest RsolvApi.Security.Patterns.Php
  doctest RsolvApi.Security.Patterns.Php.SqlInjectionConcat
  doctest RsolvApi.Security.Patterns.Php.SqlInjectionInterpolation
  doctest RsolvApi.Security.Patterns.Php.CommandInjection
  doctest RsolvApi.Security.Patterns.Php.XssEcho
  
  # Test CVE patterns
  doctest RsolvApi.Security.Patterns.Cve
  
  # Test Ruby patterns
  doctest RsolvApi.Security.Patterns.Ruby
  doctest RsolvApi.Security.Patterns.Ruby.MissingAuthentication
  doctest RsolvApi.Security.Patterns.Ruby.MassAssignment
  doctest RsolvApi.Security.Patterns.Ruby.HardcodedSecrets
  doctest RsolvApi.Security.Patterns.Ruby.SqlInjectionInterpolation
  doctest RsolvApi.Security.Patterns.Ruby.CommandInjection
  doctest RsolvApi.Security.Patterns.Ruby.XpathInjection
  doctest RsolvApi.Security.Patterns.Ruby.LdapInjection
  doctest RsolvApi.Security.Patterns.Ruby.WeakRandom
  doctest RsolvApi.Security.Patterns.Ruby.DebugModeEnabled
  doctest RsolvApi.Security.Patterns.Ruby.EvalUsage
  doctest RsolvApi.Security.Patterns.Ruby.WeakPasswordStorage
  doctest RsolvApi.Security.Patterns.Ruby.UnsafeDeserializationMarshal
  doctest RsolvApi.Security.Patterns.Ruby.UnsafeYaml
  doctest RsolvApi.Security.Patterns.Ruby.InsufficientLogging
  doctest RsolvApi.Security.Patterns.Ruby.SsrfOpenUri
  doctest RsolvApi.Security.Patterns.Ruby.XssErbRaw
  doctest RsolvApi.Security.Patterns.Ruby.PathTraversal
  doctest RsolvApi.Security.Patterns.Ruby.OpenRedirect
  doctest RsolvApi.Security.Patterns.Ruby.InsecureCookie
end