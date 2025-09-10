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
    # Ensure the application is started FIRST
    Application.ensure_all_started(:rsolv)
    
    # Wait for Repo to be available
    case Process.whereis(Rsolv.Repo) do
      nil ->
        # Repo process not found, wait for it
        Enum.reduce_while(1..30, nil, fn attempt, _ ->
          case Process.whereis(Rsolv.Repo) do
            nil when attempt < 30 ->
              Process.sleep(100)
              {:cont, nil}
            nil ->
              raise "Rsolv.Repo process never started after 3 seconds"
            _pid ->
              {:halt, :ok}
          end
        end)
      _pid ->
        :ok
    end
    
    # Now start the sandbox
    pid = Ecto.Adapters.SQL.Sandbox.start_owner!(Rsolv.Repo, shared: not tags[:async])
    on_exit(fn -> Ecto.Adapters.SQL.Sandbox.stop_owner(pid) end)
    
    # No longer need to reset test customers since LegacyAccounts is removed
    :ok
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