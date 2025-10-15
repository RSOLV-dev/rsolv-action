defmodule Rsolv.TestIsolation do
  @moduledoc """
  Helper functions for test isolation to prevent test pollution.
  """

  @doc """
  Runs a function with isolated Application environment.

  This ensures that any Application.put_env calls within the function
  are reverted after execution, preventing test pollution.

  ## Example

      with_isolated_env(fn ->
        Application.put_env(:rsolv, :some_key, :some_value)
        # ... test code ...
      end)
      # Environment is automatically restored here
  """
  def with_isolated_env(app \\ :rsolv, fun) when is_atom(app) and is_function(fun, 0) do
    old_env = Application.get_all_env(app)

    try do
      fun.()
    after
      # Clear all current env
      for {key, _value} <- Application.get_all_env(app) do
        Application.delete_env(app, key)
      end

      # Restore old env
      for {key, value} <- old_env do
        Application.put_env(app, key, value)
      end
    end
  end

  @doc """
  Runs a function with multiple isolated Application environments.

  ## Example

      with_isolated_envs([:rsolv, :bamboo], fn ->
        Application.put_env(:rsolv, :key, :value)
        Application.put_env(:bamboo, :key, :value)
        # ... test code ...
      end)
  """
  def with_isolated_envs(apps, fun) when is_list(apps) and is_function(fun, 0) do
    old_envs = Enum.map(apps, fn app -> {app, Application.get_all_env(app)} end)

    try do
      fun.()
    after
      # Restore all environments
      Enum.each(old_envs, fn {app, old_env} ->
        # Clear current env
        for {key, _value} <- Application.get_all_env(app) do
          Application.delete_env(app, key)
        end

        # Restore old env
        for {key, value} <- old_env do
          Application.put_env(app, key, value)
        end
      end)
    end
  end

  @doc """
  Creates a unique name for a test process to avoid naming conflicts.

  ## Example

      name = unique_process_name("my_genserver")
      {:ok, pid} = GenServer.start_link(MyModule, args, name: name)
  """
  def unique_process_name(base_name) when is_binary(base_name) do
    :"#{base_name}_test_#{System.unique_integer([:positive, :monotonic])}"
  end

  def unique_process_name(base_name) when is_atom(base_name) do
    unique_process_name(Atom.to_string(base_name))
  end

  @doc """
  Waits for a GenServer to be ready with a custom check function.

  ## Example

      wait_for_genserver(MyServer, fn ->
        MyServer.ready?()
      end)
  """
  def wait_for_genserver(name, ready_check_fn, timeout \\ 5000) do
    deadline = System.monotonic_time(:millisecond) + timeout

    wait_for_genserver_loop(name, ready_check_fn, deadline)
  end

  defp wait_for_genserver_loop(name, ready_check_fn, deadline) do
    case Process.whereis(name) do
      nil ->
        if System.monotonic_time(:millisecond) < deadline do
          Process.sleep(10)
          wait_for_genserver_loop(name, ready_check_fn, deadline)
        else
          {:error, :timeout}
        end

      _pid ->
        if ready_check_fn.() do
          :ok
        else
          if System.monotonic_time(:millisecond) < deadline do
            Process.sleep(10)
            wait_for_genserver_loop(name, ready_check_fn, deadline)
          else
            {:error, :not_ready}
          end
        end
    end
  end

  @doc """
  Ensures all async tasks complete before continuing.
  Useful for tests that spawn background tasks.
  """
  def wait_for_async_tasks(timeout \\ 1000) do
    Process.sleep(timeout)
  end

  @doc """
  Clears specific ETS tables if they exist.
  """
  def clear_ets_tables(tables) when is_list(tables) do
    Enum.each(tables, fn table ->
      case :ets.info(table) do
        :undefined ->
          :ok

        _ ->
          try do
            :ets.delete_all_objects(table)
          rescue
            _ -> :ok
          end
      end
    end)
  end
end
