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
      cve_2019_5418()
    ]
  end
  
  
  @doc """
  CVE-2019-5418 - File Content Disclosure pattern.
  
  Detects path traversal vulnerability in render file allowing arbitrary file disclosure.
  """
  def cve_2019_5418 do
    %Pattern{
      id: "rails-cve-2019-5418",
      name: "CVE-2019-5418 - File Content Disclosure",
      description: "Path traversal vulnerability in render file allowing arbitrary file disclosure",
      type: :path_traversal,
      severity: :critical,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        ~r/render\s+file:\s*params\[/,
        ~r/render\s+file:\s*["'`]#\{Rails\.root\}.*?#\{[^}]*params/,
        ~r/render\s+template:\s*params\[.*?path/,
        ~r/render\s+partial:\s*["'`]\.\.\/.*?#\{[^}]*params/
      ],
      default_tier: :protected,
      cwe_id: "CWE-22",
      owasp_category: "A01:2021",
      recommendation: "Never use user input directly in Rails render file/template. Use predefined Rails templates or validate against allowlist.",
      test_cases: %{
        vulnerable: [
          "render file: params[:template]"
        ],
        safe: [
          "allowed = [\"user\", \"admin\"]\nrender template: allowed.include?(params[:type]) ? params[:type] : \"default\""
        ]
      }
    }
  end
end