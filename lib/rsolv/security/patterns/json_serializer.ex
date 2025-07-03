defmodule Rsolv.Security.Patterns.JSONSerializer do
  @moduledoc """
  Handles JSON serialization of patterns, converting Elixir regex objects
  to a format that can be encoded with native JSON (Elixir 1.18+).
  """

  @doc """
  Prepares a pattern for JSON encoding by converting regex objects to maps.
  
  ## Examples
  
      iex> prepare_for_json(~r/test/)
      %{"__type__" => "regex", "source" => "test", "flags" => []}
      
      iex> prepare_for_json(~r/test/i)
      %{"__type__" => "regex", "source" => "test", "flags" => ["i"]}
  """
  def prepare_for_json(%Regex{} = regex) do
    %{
      "__type__" => "regex",
      "source" => Regex.source(regex),
      "flags" => regex_flags_to_list(regex)
    }
  end

  def prepare_for_json(%{__struct__: _} = struct) do
    # Convert struct to map and process recursively
    struct
    |> Map.from_struct()
    |> prepare_for_json()
  end
  
  def prepare_for_json(data) when is_map(data) do
    data
    |> Enum.map(fn {key, value} -> {key, prepare_for_json(value)} end)
    |> Map.new()
  end

  def prepare_for_json(data) when is_list(data) do
    Enum.map(data, &prepare_for_json/1)
  end

  def prepare_for_json(data), do: data

  # Extracts regex flags as a list of strings
  defp regex_flags_to_list(regex) do
    regex
    |> Regex.opts()
    |> Enum.map(fn
      :caseless -> "i"
      :multiline -> "m"
      :dotall -> "s"
      :extended -> "x"
      :unicode -> "u"
      {:newline, _} -> "newline"
      flag when is_atom(flag) -> Atom.to_string(flag)
      flag -> inspect(flag)
    end)
    |> Enum.sort()
  end

  @doc """
  Encodes data to JSON using native Elixir JSON module.
  Automatically prepares regex objects for serialization.
  """
  def encode!(data) do
    data
    |> prepare_for_json()
    |> JSON.encode!()
  end

  @doc """
  Encodes data to JSON, returning {:ok, json} or {:error, reason}.
  """
  def encode(data) do
    prepared = prepare_for_json(data)
    
    try do
      {:ok, JSON.encode!(prepared)}
    rescue
      e -> {:error, Exception.message(e)}
    end
  end
end