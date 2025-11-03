defmodule RsolvWeb.Helpers.DashboardHelpers do
  @moduledoc """
  Helper functions for formatting and displaying dashboard data.
  """

  require Logger

  @doc """
  Format a DateTime or timestamp string for display.

  ## Examples

      iex> format_datetime(~U[2023-05-20 12:34:56Z])
      "May 20, 2023 12:34 PM"

      iex> format_datetime("2023-05-20T12:34:56Z")
      "May 20, 2023 12:34 PM"
  """
  def format_datetime(%DateTime{} = datetime) do
    Calendar.strftime(datetime, "%b %d, %Y %I:%M %p")
  end

  def format_datetime(timestamp) when is_binary(timestamp) do
    case DateTime.from_iso8601(timestamp) do
      {:ok, datetime, _} ->
        format_datetime(datetime)

      _ ->
        # Try parsing just the date part
        case Date.from_iso8601(String.slice(timestamp, 0, 10)) do
          {:ok, date} -> Calendar.strftime(date, "%b %d, %Y")
          _ -> timestamp
        end
    end
  end

  def format_datetime(_), do: "Unknown"

  @doc """
  Format a duration in seconds as a human-readable string.

  ## Examples

      iex> format_duration(65)
      "1m 5s"

      iex> format_duration(3665)
      "1h 1m 5s"
  """
  def format_duration(seconds) when is_integer(seconds) and seconds > 0 do
    hours = div(seconds, 3600)
    minutes = div(rem(seconds, 3600), 60)
    remaining_seconds = rem(seconds, 60)

    cond do
      hours > 0 -> "#{hours}h #{minutes}m #{remaining_seconds}s"
      minutes > 0 -> "#{minutes}m #{remaining_seconds}s"
      true -> "#{remaining_seconds}s"
    end
  end

  def format_duration(_), do: "0s"

  @doc """
  Parse additional data JSON string.
  """
  def try_parse_additional_data(json_string) when is_binary(json_string) do
    case JSON.decode(json_string) do
      {:ok, data} -> data
      _ -> %{}
    end
  end

  def try_parse_additional_data(_), do: %{}

  @doc """
  Check if chart data is empty or contains usable data.
  Returns true if the data is empty or unusable, false otherwise.

  ## Examples

      iex> is_empty_chart_data([])
      true

      iex> is_empty_chart_data(nil)
      true

      iex> is_empty_chart_data([%{count: 1}])
      false
  """
  def is_empty_chart_data(data) do
    try do
      cond do
        is_nil(data) -> true
        not is_list(data) and not is_map(data) -> true
        is_list(data) and Enum.empty?(data) -> true
        is_map(data) and map_size(data) == 0 -> true
        true -> false
      end
    rescue
      e ->
        Logger.warning("Error checking chart data",
          metadata: %{
            error: inspect(e),
            data_type: inspect(data)
          }
        )

        # Assume empty on error for safety
        true
    end
  end

  @doc """
  Safely extract data from a nested map/struct with a default value.

  ## Examples

      iex> safe_get(%{a: %{b: 1}}, [:a, :b], 0)
      1

      iex> safe_get(%{a: %{c: 1}}, [:a, :b], 0)
      0

      iex> safe_get(nil, [:a, :b], 0)
      0
  """
  def safe_get(data, keys, default \\ nil) do
    try do
      get_in_path(data, keys, default)
    rescue
      _ -> default
    end
  end

  # Helper function for safe_get
  defp get_in_path(nil, _, default), do: default
  defp get_in_path(data, [], _), do: data

  defp get_in_path(data, [key | rest], default) when is_map(data) do
    case Map.get(data, key) do
      nil -> default
      value -> get_in_path(value, rest, default)
    end
  end

  defp get_in_path(_, _, default), do: default

  @doc """
  Determines whether to show the setup wizard to a customer.

  The wizard visibility is controlled by:
  - `wizard_preference`: "auto" (default), "hidden" (manually dismissed), or "shown" (manually re-entered)
  - `first_scan_at`: Whether the customer has completed their first scan

  ## Logic
  - "auto": Show wizard only if no scans completed (`first_scan_at` is nil)
  - "hidden": Never show wizard (manually dismissed)
  - "shown": Always show wizard (manually re-entered)
  - nil customer or invalid preference: Don't show wizard

  ## Examples

      iex> show_wizard?(%Customer{wizard_preference: "auto", first_scan_at: nil})
      true

      iex> show_wizard?(%Customer{wizard_preference: "auto", first_scan_at: ~U[2025-10-20 12:00:00Z]})
      false

      iex> show_wizard?(%Customer{wizard_preference: "hidden", first_scan_at: nil})
      false

      iex> show_wizard?(%Customer{wizard_preference: "shown", first_scan_at: ~U[2025-10-20 12:00:00Z]})
      true
  """
  def show_wizard?(nil), do: false

  def show_wizard?(%{wizard_preference: "auto", first_scan_at: nil}), do: true
  def show_wizard?(%{wizard_preference: "auto", first_scan_at: _}), do: false

  def show_wizard?(%{wizard_preference: "hidden"}), do: false
  def show_wizard?(%{wizard_preference: "shown"}), do: true

  # Default case for invalid wizard_preference or missing fields
  def show_wizard?(_), do: false
end
