defmodule RsolvApi.Security.Patterns.Django do
  @moduledoc """
  Django framework security patterns for detecting vulnerabilities.
  
  This module contains 19 security patterns specifically designed for Django
  framework code. These patterns complement the base Python patterns with
  Django-specific vulnerability detection.
  """
  
  alias RsolvApi.Security.Patterns.Django.OrmInjection
  alias RsolvApi.Security.Patterns.Django.NosqlInjection
  alias RsolvApi.Security.Patterns.Django.TemplateXss
  alias RsolvApi.Security.Patterns.Django.TemplateInjection
  alias RsolvApi.Security.Patterns.Django.DebugSettings
  alias RsolvApi.Security.Patterns.Django.InsecureSession
  alias RsolvApi.Security.Patterns.Django.MissingSecurityMiddleware
  alias RsolvApi.Security.Patterns.Django.BrokenAuth
  alias RsolvApi.Security.Patterns.Django.AuthorizationBypass
  alias RsolvApi.Security.Patterns.Django.CsrfBypass
  alias RsolvApi.Security.Patterns.Django.Clickjacking
  alias RsolvApi.Security.Patterns.Django.ModelInjection
  alias RsolvApi.Security.Patterns.Django.MassAssignment
  alias RsolvApi.Security.Patterns.Django.UnsafeUrlPatterns
  alias RsolvApi.Security.Patterns.Django.Cve202133203
  alias RsolvApi.Security.Patterns.Django.Cve202133571
  alias RsolvApi.Security.Patterns.Django.Cve202013254
  alias RsolvApi.Security.Patterns.Django.Cve201914234
  alias RsolvApi.Security.Patterns.Django.Cve201814574
  
  @doc """
  Returns all Django security patterns.
  
  ## Examples
  
      iex> patterns = RsolvApi.Security.Patterns.Django.all()
      iex> length(patterns)
      19
      iex> Enum.all?(patterns, &match?(%RsolvApi.Security.Pattern{}, &1))
      true
  """
  def all do
    [
      OrmInjection.pattern(),
      NosqlInjection.pattern(),
      TemplateXss.pattern(),
      TemplateInjection.pattern(),
      DebugSettings.pattern(),
      InsecureSession.pattern(),
      MissingSecurityMiddleware.pattern(),
      BrokenAuth.pattern(),
      AuthorizationBypass.pattern(),
      CsrfBypass.pattern(),
      Clickjacking.pattern(),
      ModelInjection.pattern(),
      MassAssignment.pattern(),
      UnsafeUrlPatterns.pattern(),
      Cve202133203.pattern(),
      Cve202133571.pattern(),
      Cve202013254.pattern(),
      Cve201914234.pattern(),
      Cve201814574.pattern()
    ]
  end
  
  
  # Migrated to Django.TemplateInjection module
  
  # Migrated to Django.DebugSettings module
  
  # Migrated to Django.InsecureSession module
  
  # Migrated to Django.MissingSecurityMiddleware module
  
  # Migrated to Django.BrokenAuth module
  
  # Migrated to Django.AuthorizationBypass module
  
  # Migrated to Django.CsrfBypass module
  
  # Migrated to Django.Clickjacking module
  
  # Migrated to Django.ModelInjection module
  
  # Migrated to Django.MassAssignment module
  
  # Migrated to Django.UnsafeUrlPatterns module
  
  # CVE patterns for Django
  
  # Migrated to Django.Cve202133203 module
  
  # Migrated to Django.Cve202133571 module
  
  # Migrated to Django.Cve202013254 module
  
  # Migrated to Django.Cve201914234 module
  
  # Migrated to Django.Cve201814574 module
end