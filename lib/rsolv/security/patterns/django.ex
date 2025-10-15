defmodule Rsolv.Security.Patterns.Django do
  @moduledoc """
  Django framework security patterns for detecting vulnerabilities.

  This module contains 19 security patterns specifically designed for Django
  framework code. These patterns complement the base Python patterns with
  Django-specific vulnerability detection.
  """

  alias Rsolv.Security.Patterns.Django.OrmInjection
  alias Rsolv.Security.Patterns.Django.NosqlInjection
  alias Rsolv.Security.Patterns.Django.TemplateXss
  alias Rsolv.Security.Patterns.Django.TemplateInjection
  alias Rsolv.Security.Patterns.Django.DebugSettings
  alias Rsolv.Security.Patterns.Django.InsecureSession
  alias Rsolv.Security.Patterns.Django.MissingSecurityMiddleware
  alias Rsolv.Security.Patterns.Django.BrokenAuth
  alias Rsolv.Security.Patterns.Django.AuthorizationBypass
  alias Rsolv.Security.Patterns.Django.CsrfBypass
  alias Rsolv.Security.Patterns.Django.Clickjacking
  alias Rsolv.Security.Patterns.Django.ModelInjection
  alias Rsolv.Security.Patterns.Django.MassAssignment
  alias Rsolv.Security.Patterns.Django.UnsafeUrlPatterns
  alias Rsolv.Security.Patterns.Django.Cve202133203
  alias Rsolv.Security.Patterns.Django.Cve202133571
  alias Rsolv.Security.Patterns.Django.Cve202013254
  alias Rsolv.Security.Patterns.Django.Cve201914234
  alias Rsolv.Security.Patterns.Django.Cve201814574

  @doc """
  Returns all Django security patterns.

  ## Examples

      iex> patterns = Rsolv.Security.Patterns.Django.all()
      iex> length(patterns)
      19
      iex> Enum.all?(patterns, &match?(%Rsolv.Security.Pattern{}, &1))
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
