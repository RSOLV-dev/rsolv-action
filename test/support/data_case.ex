defmodule Rsolv.DataCase do
  @moduledoc """
  This module defines the setup for tests requiring
  access to the application's data layer.

  You may define functions here to be used as helpers in
  your tests.

  Finally, if the test case interacts with the database,
  we enable the SQL sandbox, so changes done to the database
  are reverted at the end of every test. If you are using
  PostgreSQL, you can even run database tests asynchronously
  by setting `use Rsolv.DataCase, async: true`, although
  this option is not recommended for other databases.
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      alias Rsolv.Repo

      import Ecto
      import Ecto.Changeset
      import Ecto.Query
      import Rsolv.DataCase
    end
  end

  setup tags do
    # Ensure the repo is started before trying to use sandbox
    try do
      pid = Ecto.Adapters.SQL.Sandbox.start_owner!(Rsolv.Repo, shared: not tags[:async])
      on_exit(fn -> Ecto.Adapters.SQL.Sandbox.stop_owner(pid) end)
      :ok
    rescue
      error in RuntimeError ->
        if error.message =~ "could not lookup Ecto repo" do
          # Log the error for debugging
          require Logger
          Logger.error("Repo not started in DataCase, attempting to start application: #{inspect(error)}")
          # Try to start the application if needed
          Application.ensure_all_started(:rsolv)
          # Retry once
          pid = Ecto.Adapters.SQL.Sandbox.start_owner!(Rsolv.Repo, shared: not tags[:async])
          on_exit(fn -> Ecto.Adapters.SQL.Sandbox.stop_owner(pid) end)
          :ok
        else
          reraise error, __STACKTRACE__
        end
    end
  end

  @doc """
  A helper that transforms changeset errors into a map of messages.

      assert {:error, changeset} = Accounts.create_user(%{password: "short"})
      assert "should be at least 10 character(s)" in errors_on(changeset).password
      assert %{password: ["should be at least 10 character(s)"]} = errors_on(changeset)

  """
  def errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Regex.replace(~r"%{(\w+)}", message, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end