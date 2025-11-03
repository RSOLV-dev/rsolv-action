defmodule Rsolv.Security.Patterns.JSONSerializer do
  @moduledoc """
  Converts Elixir-native types to JSON-compatible representations.

  This module handles the serialization of security patterns and other data structures
  that contain types not natively supported by JSON, including:

  - **Regex** → Map with `__type__`, `source`, and `flags` fields
  - **Tuples** → Lists (recursively processed)
  - **Atoms** → Strings (except `nil`, `true`, `false`)
  - **Structs** → Maps (recursively processed)

  All conversions are applied recursively through nested data structures.

  ## Examples

      iex> prepare_for_json(~r/test/i)
      %{"__type__" => "regex", "source" => "test", "flags" => ["i"]}

      iex> prepare_for_json({:ok, "value"})
      ["ok", "value"]

      iex> prepare_for_json(%{status: :active})
      %{status: "active"}
  """

  @doc """
  Prepares data for JSON encoding by converting non-JSON-native types.

  Recursively processes the data structure, converting:
  - Regex objects to serializable maps
  - Tuples to lists
  - Atoms to strings (preserving nil and booleans)
  - Structs to maps
  - Maps and lists by processing their contents

  ## Examples

      iex> prepare_for_json(~r/test/)
      %{"__type__" => "regex", "source" => "test", "flags" => []}

      iex> prepare_for_json({:error, "failed"})
      ["error", "failed"]

      iex> prepare_for_json(%{severity: :high})
      %{severity: "high"}
  """
  # Regex objects → serializable maps
  def prepare_for_json(%Regex{} = regex) do
    %{
      "__type__" => "regex",
      "source" => Regex.source(regex),
      "flags" => extract_regex_flags(regex)
    }
  end

  # Structs → maps (then recursively processed)
  def prepare_for_json(%{__struct__: _} = struct) do
    struct
    |> Map.from_struct()
    |> prepare_for_json()
  end

  # Maps → recursively process values
  def prepare_for_json(data) when is_map(data) do
    Map.new(data, fn {key, value} -> {key, prepare_for_json(value)} end)
  end

  # Lists → recursively process elements
  def prepare_for_json(data) when is_list(data) do
    Enum.map(data, &prepare_for_json/1)
  end

  # Tuples → lists (then recursively processed)
  def prepare_for_json(data) when is_tuple(data) do
    data
    |> Tuple.to_list()
    |> prepare_for_json()
  end

  # JSON-safe atoms (nil, true, false) → unchanged
  def prepare_for_json(data) when data in [nil, true, false], do: data

  # Other atoms → strings
  def prepare_for_json(data) when is_atom(data), do: Atom.to_string(data)

  # Primitives (strings, numbers) → unchanged
  def prepare_for_json(data), do: data

  @doc """
  Encodes data to JSON, automatically converting non-JSON-native types.

  This is a convenience wrapper around `prepare_for_json/1` and `JSON.encode!/1`.

  ## Examples

      iex> encode!(%{pattern: ~r/test/})
      ~s({"pattern":{"__type__":"regex","flags":[],"source":"test"}})
  """
  def encode!(data) do
    data
    |> prepare_for_json()
    |> JSON.encode!()
  end

  @doc """
  Encodes data to JSON, returning `{:ok, json}` or `{:error, reason}`.

  ## Examples

      iex> encode(%{pattern: ~r/test/})
      {:ok, ~s({"pattern":{"__type__":"regex","flags":[],"source":"test"}})}
  """
  def encode(data) do
    {:ok, data |> prepare_for_json() |> JSON.encode!()}
  rescue
    exception -> {:error, Exception.message(exception)}
  end

  ## Private Helpers

  # Extracts regex flags as a sorted list of string representations
  defp extract_regex_flags(regex) do
    regex
    |> Regex.opts()
    |> Enum.map(&normalize_regex_flag/1)
    |> Enum.sort()
  end

  # Normalizes regex flag atoms to their string representations
  defp normalize_regex_flag(:caseless), do: "i"
  defp normalize_regex_flag(:multiline), do: "m"
  defp normalize_regex_flag(:dotall), do: "s"
  defp normalize_regex_flag(:extended), do: "x"
  defp normalize_regex_flag(:unicode), do: "u"
  defp normalize_regex_flag({:newline, _}), do: "newline"
  defp normalize_regex_flag(flag) when is_atom(flag), do: Atom.to_string(flag)
  defp normalize_regex_flag(flag), do: inspect(flag)
end
