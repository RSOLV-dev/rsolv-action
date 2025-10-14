defmodule Rsolv.IntegrationCase do
  @moduledoc """
  Test case for integration tests that need real processes.
  
  Features:
  - Always runs with async: false
  - Properly manages process lifecycle with start_supervised!
  - Ensures process cleanup between tests
  - Provides helpers for process synchronization
  """
  
  use ExUnit.CaseTemplate
  
  using do
    quote do
      use ExUnit.Case, async: false
      import Rsolv.IntegrationCase
      
      # Import helpers for process management
      import ExUnit.Callbacks
    end
  end
  
  # No default setup here - let child modules define their own setup
  
  @doc """
  Waits for a process to be registered with a timeout.
  Returns {:ok, pid} or {:error, :timeout}
  """
  def wait_for_process(name, timeout \\ 5000) do
    wait_until(timeout, fn ->
      case Process.whereis(name) do
        nil -> false
        pid -> {:ok, pid}
      end
    end)
  end
  
  @doc """
  Waits until a condition is met or timeout occurs.
  The condition function should return false to continue waiting,
  or any other value to stop waiting.
  """
  def wait_until(timeout, condition_fn) do
    start_time = System.monotonic_time(:millisecond)
    do_wait_until(start_time, timeout, condition_fn)
  end
  
  defp do_wait_until(start_time, timeout, condition_fn) do
    case condition_fn.() do
      false ->
        elapsed = System.monotonic_time(:millisecond) - start_time
        if elapsed < timeout do
          Process.sleep(10)
          do_wait_until(start_time, timeout, condition_fn)
        else
          {:error, :timeout}
        end
      result ->
        result
    end
  end
  
  @doc """
  Starts a supervised process and waits for it to be ready.
  """
  def start_supervised_and_wait!(spec, name) do
    pid = start_supervised!(spec)
    
    # Wait for the process to register its name
    case wait_for_process(name) do
      {:ok, ^pid} -> pid
      _ -> 
        flunk("Process #{inspect(name)} did not start properly")
    end
  end
end