defmodule RsolvApi.Security.Patterns.Rails do
  @moduledoc """
  Ruby on Rails framework-specific security patterns.
  
  This module contains 20 security patterns specifically designed for Rails
  applications. These patterns detect Rails-specific vulnerabilities beyond 
  base Ruby patterns. All patterns are tagged with frameworks: ["rails"].
  """
  
  alias RsolvApi.Security.Pattern
  alias RsolvApi.Security.Patterns.Rails.MissingStrongParameters
  alias RsolvApi.Security.Patterns.Rails.DangerousAttrAccessible
  alias RsolvApi.Security.Patterns.Rails.ActiverecordInjection
  alias RsolvApi.Security.Patterns.Rails.DynamicFinderInjection
  alias RsolvApi.Security.Patterns.Rails.ErbInjection
  alias RsolvApi.Security.Patterns.Rails.TemplateXss
  alias RsolvApi.Security.Patterns.Rails.UnsafeRouteConstraints
  alias RsolvApi.Security.Patterns.Rails.UnsafeGlobbing
  alias RsolvApi.Security.Patterns.Rails.InsecureSessionConfig
  alias RsolvApi.Security.Patterns.Rails.DangerousProductionConfig
  alias RsolvApi.Security.Patterns.Rails.InsecureCors
  alias RsolvApi.Security.Patterns.Rails.ActionmailerInjection
  alias RsolvApi.Security.Patterns.Rails.SessionFixation
  alias RsolvApi.Security.Patterns.Rails.InsecureSessionData
  alias RsolvApi.Security.Patterns.Rails.Cve202222577
  alias RsolvApi.Security.Patterns.Rails.Cve202122881
  alias RsolvApi.Security.Patterns.Rails.CallbackSecurityBypass
  alias RsolvApi.Security.Patterns.Rails.Cve20195418
  
  @doc """
  Returns all Rails security patterns.
  
  ## Examples
  
      iex> patterns = RsolvApi.Security.Patterns.Rails.all()
      iex> length(patterns)
      20
      iex> Enum.all?(patterns, &match?(%Pattern{}, &1))
      true
      iex> Enum.all?(patterns, & &1.frameworks == ["rails"])
      true
  """
  def all do
    [
      MissingStrongParameters.pattern(),
      DangerousAttrAccessible.pattern(),
      ActiverecordInjection.pattern(),
      DynamicFinderInjection.pattern(),
      ErbInjection.pattern(),
      TemplateXss.pattern(),
      UnsafeRouteConstraints.pattern(),
      UnsafeGlobbing.pattern(),
      InsecureSessionConfig.pattern(),
      DangerousProductionConfig.pattern(),
      InsecureCors.pattern(),
      ActionmailerInjection.pattern(),
      SessionFixation.pattern(),
      InsecureSessionData.pattern(),
      Cve202222577.pattern(),
      Cve202122881.pattern(),
      CallbackSecurityBypass.pattern(),
      Cve20195418.pattern()
    ]
  end
  
end