defmodule RsolvWeb.Helpers.ChangesetHelper do
  @moduledoc """
  Helper functions for formatting Ecto changeset errors into user-friendly messages.

  Provides consistent error formatting across controllers and LiveViews.
  """

  @doc """
  Formats Ecto changeset errors into a human-readable string.

  ## Examples

      iex> changeset = Ecto.Changeset.cast({%{}, %{email: :string}}, %{}, [:email])
      iex> changeset = Ecto.Changeset.validate_required(changeset, [:email])
      iex> RsolvWeb.Helpers.ChangesetHelper.format_errors(changeset)
      "email can't be blank"

  """
  @spec format_errors(Ecto.Changeset.t()) :: String.t()
  def format_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
    |> Enum.map(fn {field, errors} ->
      "#{field} #{Enum.join(errors, ", ")}"
    end)
    |> Enum.join("; ")
  end
end
