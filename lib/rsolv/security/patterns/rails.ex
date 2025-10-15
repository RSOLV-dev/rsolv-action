defmodule Rsolv.Security.Patterns.Rails do
  @moduledoc """
  Ruby on Rails framework-specific security patterns.

  This module contains 20 security patterns specifically designed for Rails
  applications. These patterns detect Rails-specific vulnerabilities beyond
  base Ruby patterns. All patterns are tagged with frameworks: ["rails"].
  """

  alias Rsolv.Security.Patterns.Rails.MissingStrongParameters
  alias Rsolv.Security.Patterns.Rails.DangerousAttrAccessible
  alias Rsolv.Security.Patterns.Rails.ActiverecordInjection
  alias Rsolv.Security.Patterns.Rails.DynamicFinderInjection
  alias Rsolv.Security.Patterns.Rails.ErbInjection
  alias Rsolv.Security.Patterns.Rails.TemplateXss
  alias Rsolv.Security.Patterns.Rails.UnsafeRouteConstraints
  alias Rsolv.Security.Patterns.Rails.UnsafeGlobbing
  alias Rsolv.Security.Patterns.Rails.InsecureSessionConfig
  alias Rsolv.Security.Patterns.Rails.DangerousProductionConfig
  alias Rsolv.Security.Patterns.Rails.InsecureCors
  alias Rsolv.Security.Patterns.Rails.ActionmailerInjection
  alias Rsolv.Security.Patterns.Rails.SessionFixation
  alias Rsolv.Security.Patterns.Rails.InsecureSessionData
  alias Rsolv.Security.Patterns.Rails.Cve202222577
  alias Rsolv.Security.Patterns.Rails.Cve202122881
  alias Rsolv.Security.Patterns.Rails.CallbackSecurityBypass
  alias Rsolv.Security.Patterns.Rails.Cve20195418

  @doc """
  Returns all Rails security patterns.

  ## Examples

      iex> patterns = Rsolv.Security.Patterns.Rails.all()
      iex> length(patterns)
      20
      iex> Enum.all?(patterns, &match?(%Rsolv.Security.Pattern{}, &1))
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
