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
  
  # Test Elixir patterns
  doctest RsolvApi.Security.Patterns.Elixir
  
  # Test PHP patterns
  doctest RsolvApi.Security.Patterns.Php
  doctest RsolvApi.Security.Patterns.Php.SqlInjectionConcat
  doctest RsolvApi.Security.Patterns.Php.SqlInjectionInterpolation
  
  # Test CVE patterns
  doctest RsolvApi.Security.Patterns.Cve
  
  # Ruby module is excluded due to compilation issues
end