defmodule Rsolv.Security.Pattern do
  @moduledoc """
  Defines the structure for security patterns.

  Each pattern represents a security vulnerability detection rule with:
  - Metadata (id, name, description)
  - Detection rules (regex patterns)
  - Categorization (type, severity, languages)
  - Standards mapping (cwe_id, owasp_category)
  - Educational content (recommendation, test_cases)
  """

  @type severity :: :low | :medium | :high | :critical
  @type vulnerability_type ::
          :sql_injection
          | :xss
          | :command_injection
          | :path_traversal
          | :weak_crypto
          | :hardcoded_secret
          | :authentication
          | :csrf
          | :ssrf
          | :xxe
          | :deserialization
          | :information_disclosure
          | :file_upload
          | :rce
          | :open_redirect
          | :ldap_injection
          | :xpath_injection
          | :insecure_random
          | :timing_attack
          | :mass_assignment
          | :resource_exhaustion
          | :dos
          | :session_management
          | :input_validation
          | :logging
          | :cve
          | :debug_mode
          | :broken_access_control
          | :security_misconfiguration

  @type target_scope ::
          :any
          | :models
          | :controllers
          | :views
          | :configs
          | :routes
          | :middleware
          | :helpers
          | :tests

  @type file_targeting ::
          %{
            scope: target_scope(),
            include_paths: [String.t()] | nil,
            exclude_paths: [String.t()] | nil,
            include_extensions: [String.t()] | nil,
            exclude_extensions: [String.t()] | nil
          }
          | nil

  @type t :: %__MODULE__{
          id: String.t(),
          name: String.t(),
          description: String.t(),
          type: vulnerability_type(),
          severity: severity(),
          languages: [String.t()],
          frameworks: [String.t()] | nil,
          regex: Regex.t() | [Regex.t()],
          cwe_id: String.t() | nil,
          owasp_category: String.t() | nil,
          recommendation: String.t(),
          test_cases: %{
            vulnerable: [String.t()],
            safe: [String.t()]
          },
          file_targeting: file_targeting()
        }

  @enforce_keys [
    :id,
    :name,
    :description,
    :type,
    :severity,
    :languages,
    :regex,
    :recommendation,
    :test_cases
  ]

  defstruct [
    :id,
    :name,
    :description,
    :type,
    :severity,
    :languages,
    :frameworks,
    :regex,
    :cwe_id,
    :owasp_category,
    :recommendation,
    :test_cases,
    :file_targeting
  ]

  @doc """
  Validates that a pattern has all required fields and valid values.

  ## Examples

      iex> pattern = %Pattern{
      ...>   id: "test-pattern",
      ...>   name: "Test",
      ...>   description: "Test pattern",
      ...>   type: :sql_injection,
      ...>   severity: :high,
      ...>   languages: ["javascript"],
      ...>   regex: ~r/test/,
      ...>   recommendation: "Fix it",
      ...>   test_cases: %{vulnerable: ["bad"], safe: ["good"]}
      ...> }
      iex> Pattern.valid?(pattern)
      true
  """
  def valid?(%__MODULE__{} = pattern) do
    valid_id?(pattern.id) &&
      valid_severity?(pattern.severity) &&
      valid_languages?(pattern.languages) &&
      valid_regex?(pattern.regex) &&
      valid_test_cases?(pattern.test_cases)
  end

  defp valid_id?(id) when is_binary(id) do
    Regex.match?(~r/^[a-z0-9-]+$/, id)
  end

  defp valid_id?(_), do: false

  defp valid_severity?(severity) when severity in [:low, :medium, :high, :critical], do: true
  defp valid_severity?(_), do: false

  defp valid_languages?(languages) when is_list(languages) do
    length(languages) > 0 && Enum.all?(languages, &is_binary/1)
  end

  defp valid_languages?(_), do: false

  defp valid_regex?(%Regex{}), do: true

  defp valid_regex?(list) when is_list(list) do
    length(list) > 0 && Enum.all?(list, &match?(%Regex{}, &1))
  end

  defp valid_regex?(_), do: false

  defp valid_test_cases?(%{vulnerable: vuln, safe: safe})
       when is_list(vuln) and is_list(safe) do
    length(vuln) > 0 && length(safe) > 0 &&
      Enum.all?(vuln, &is_binary/1) && Enum.all?(safe, &is_binary/1)
  end

  defp valid_test_cases?(_), do: false

  @doc """
  Converts a pattern to the API response format.

  ## Examples

      iex> pattern = %Pattern{
      ...>   id: "js-sql-injection",
      ...>   name: "SQL Injection",
      ...>   severity: :high,
      ...>   # ... other fields
      ...> }
      iex> Pattern.to_api_format(pattern)
      %{
        id: "js-sql-injection",
        name: "SQL Injection", 
        severity: "high",
        # ...
      }
  """
  def to_api_format(%__MODULE__{} = pattern) do
    %{
      id: pattern.id,
      name: pattern.name,
      description: pattern.description,
      type: to_string(pattern.type),
      severity: to_string(pattern.severity),
      languages: pattern.languages,
      regex_patterns: regex_to_strings(pattern.regex),
      cwe_id: pattern.cwe_id,
      owasp_category: pattern.owasp_category,
      recommendation: pattern.recommendation,
      examples: %{
        vulnerable: pattern.test_cases.vulnerable,
        safe: pattern.test_cases.safe
      }
    }
  end

  defp regex_to_strings(%Regex{} = regex), do: [Regex.source(regex)]

  defp regex_to_strings(list) when is_list(list) do
    Enum.map(list, &Regex.source/1)
  end
end
