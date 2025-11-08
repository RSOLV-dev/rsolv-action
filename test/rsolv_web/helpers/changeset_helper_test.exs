defmodule RsolvWeb.Helpers.ChangesetHelperTest do
  use ExUnit.Case, async: true
  doctest RsolvWeb.Helpers.ChangesetHelper

  alias RsolvWeb.Helpers.ChangesetHelper

  describe "format_errors/1" do
    test "formats single field error" do
      changeset =
        {%{}, %{email: :string}}
        |> Ecto.Changeset.cast(%{}, [:email])
        |> Ecto.Changeset.validate_required([:email])

      assert ChangesetHelper.format_errors(changeset) == "email can't be blank"
    end

    test "formats multiple field errors" do
      changeset =
        {%{}, %{email: :string, name: :string}}
        |> Ecto.Changeset.cast(%{}, [:email, :name])
        |> Ecto.Changeset.validate_required([:email, :name])

      error_string = ChangesetHelper.format_errors(changeset)

      # Both errors should be present (order may vary)
      assert error_string =~ "email can't be blank"
      assert error_string =~ "name can't be blank"
    end

    test "formats validation error with interpolation" do
      changeset =
        {%{}, %{password: :string}}
        |> Ecto.Changeset.cast(%{password: "short"}, [:password])
        |> Ecto.Changeset.validate_length(:password, min: 8)

      error_string = ChangesetHelper.format_errors(changeset)

      assert error_string =~ "password should be at least 8 character"
    end

    test "handles empty changeset" do
      changeset = Ecto.Changeset.cast({%{}, %{}}, %{}, [])

      assert ChangesetHelper.format_errors(changeset) == ""
    end
  end
end
