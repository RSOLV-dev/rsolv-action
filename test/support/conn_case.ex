defmodule RsolvWeb.ConnCase do
  @moduledoc """
  This module defines the test case to be used by
  tests that require setting up a connection.

  Such tests rely on `Phoenix.ConnTest` and also
  import other functionality to make it easier
  to build common data structures and query the data layer.

  Finally, if the test case interacts with the database,
  we enable the SQL sandbox, so changes done to the database
  are reverted at the end of every test. If you are using
  PostgreSQL, you can even run database tests asynchronously
  by setting `use RsolvWeb.ConnCase, async: true`, although
  this option is not recommended for other databases.
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      # The default endpoint for testing
      @endpoint RsolvWeb.Endpoint

      use RsolvWeb, :verified_routes

      # Import conveniences for testing with connections
      import Plug.Conn
      import Phoenix.ConnTest
      import RsolvWeb.ConnCase
    end
  end
  
  @doc """
  Logs in a customer for testing.
  """
  def log_in_customer(conn, customer) do
    token = Rsolv.Customers.generate_customer_session_token(customer)
    
    conn
    |> Phoenix.ConnTest.init_test_session(%{})
    |> Plug.Conn.put_session(:customer_token, token)
  end

  setup tags do
    # Ensure the application is started
    Application.ensure_all_started(:rsolv)
    
    # Wait for endpoint to be ready (it creates an ETS table internally)
    ensure_endpoint_started()
    
    # Clear Mnesia customer sessions table to prevent test interference
    try do
      :mnesia.clear_table(:customer_sessions_mnesia)
    rescue
      _ -> :ok
    end
    
    # Ensure the repo is started before trying to use sandbox
    try do
      pid = Ecto.Adapters.SQL.Sandbox.start_owner!(Rsolv.Repo, shared: not tags[:async])
      on_exit(fn -> Ecto.Adapters.SQL.Sandbox.stop_owner(pid) end)
      
      # No longer need to reset test customers since LegacyAccounts is removed
      
      {:ok, conn: Phoenix.ConnTest.build_conn()}
    rescue
      error in RuntimeError ->
        if error.message =~ "could not lookup Ecto repo" do
          # Log the error for debugging
          require Logger
          Logger.error("Repo not started, attempting to start application: #{inspect(error)}")
          # Try to start the application if needed
          Application.ensure_all_started(:rsolv)
          # Retry once
          pid = Ecto.Adapters.SQL.Sandbox.start_owner!(Rsolv.Repo, shared: not tags[:async])
          on_exit(fn -> Ecto.Adapters.SQL.Sandbox.stop_owner(pid) end)
          {:ok, conn: Phoenix.ConnTest.build_conn()}
        else
          reraise error, __STACKTRACE__
        end
    end
  end
  
  # Helper to ensure endpoint is fully started and ready
  defp ensure_endpoint_started do
    # Try to access the endpoint's config which uses its ETS table
    # If the ETS table doesn't exist, this will fail
    max_attempts = 50
    retry_delay = 10 # milliseconds
    
    Enum.reduce_while(1..max_attempts, nil, fn attempt, _ ->
      try do
        # This will fail if the ETS table isn't created yet
        RsolvWeb.Endpoint.config(:secret_key_base)
        {:halt, :ok}
      rescue
        ArgumentError ->
          if attempt < max_attempts do
            Process.sleep(retry_delay)
            {:cont, nil}
          else
            raise "Endpoint ETS table not available after #{max_attempts * retry_delay}ms"
          end
      end
    end)
  end
end
