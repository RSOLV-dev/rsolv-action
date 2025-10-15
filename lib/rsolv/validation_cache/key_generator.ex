defmodule Rsolv.ValidationCache.KeyGenerator do
  @moduledoc """
  Generates deterministic cache keys for vulnerability validations.

  Cache keys are scoped to forge accounts and include all location information
  to ensure proper invalidation when files change.
  """

  @doc """
  Generates a cache key for a vulnerability validation result.

  The key format is:
  `forge_account_id/repository/[sorted_locations]:vulnerability_type`

  ## Parameters
    - forge_account_id: Integer ID or String identifier of the forge account
    - repository: String repository identifier (e.g., "RSOLV-dev/nodegoat")
    - locations: List of location maps with :file_path and :line keys
    - vulnerability_type: String vulnerability type (e.g., "sql-injection")

  ## Examples

      iex> generate_key(123, "org/repo", [%{file_path: "app.js", line: 42}], "xss")
      "123/org/repo/[app.js:42]:xss"

      iex> generate_key("test-forge-14", "org/repo", [%{file_path: "app.js", line: 42}], "xss")
      "test-forge-14/org/repo/[app.js:42]:xss"

      iex> generate_key(123, "org/repo", [
      ...>   %{file_path: "lib/db.js", line: 10},
      ...>   %{file_path: "api/endpoint.js", line: 30}
      ...> ], "sql-injection")
      "123/org/repo/[api/endpoint.js:30,lib/db.js:10]:sql-injection"

  ## Raises
    - ArgumentError if locations list is empty
  """
  def generate_key(forge_account_id, repository, locations, vulnerability_type)
      when (is_integer(forge_account_id) or is_binary(forge_account_id)) and
             is_binary(repository) and
             is_list(locations) and
             is_binary(vulnerability_type) do
    validate_locations!(locations)

    location_string = format_locations(locations)
    "#{forge_account_id}/#{repository}/[#{location_string}]:#{vulnerability_type}"
  end

  defp validate_locations!([]), do: raise(ArgumentError, "Locations cannot be empty")
  defp validate_locations!(locations), do: locations

  defp format_locations(locations) do
    locations
    |> Enum.map(&format_single_location/1)
    |> Enum.sort()
    |> Enum.join(",")
  end

  defp format_single_location(%{file_path: path, line: line}) do
    "#{path}:#{line}"
  end
end
