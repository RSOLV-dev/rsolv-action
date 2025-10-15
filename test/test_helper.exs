# Hook into ExUnit lifecycle
defmodule TestTracer do
  use GenServer

  def start_link(_) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def init(_) do
    IO.puts("TestTracer: Starting at #{DateTime.utc_now()}")
    Process.send_after(self(), :check_14s, 14_000)
    Process.send_after(self(), :check_15s, 15_000)
    Process.send_after(self(), :check_16s, 16_000)
    {:ok, %{start: System.monotonic_time(:millisecond)}}
  end

  def handle_info(:check_14s, state) do
    IO.puts("TestTracer: 14 seconds since ExUnit start")
    {:noreply, state}
  end

  def handle_info(:check_15s, state) do
    IO.puts("TestTracer: 15 seconds since ExUnit start - CRITICAL POINT")
    {:noreply, state}
  end

  def handle_info(:check_16s, state) do
    IO.puts("TestTracer: 16 seconds - SURVIVED!")
    {:noreply, state}
  end
end

# Start the tracer before ExUnit
{:ok, _pid} = TestTracer.start_link([])
# Ensure the application is started
{:ok, _} = Application.ensure_all_started(:rsolv)

# Wait for the repo to be ready
max_retries = 30
# milliseconds
retry_delay = 100

# First, ensure the repo process is started
case Process.whereis(Rsolv.Repo) do
  nil ->
    # Repo process not found, wait for it
    Enum.reduce_while(1..max_retries, nil, fn attempt, _ ->
      case Process.whereis(Rsolv.Repo) do
        nil when attempt < max_retries ->
          Process.sleep(retry_delay)
          {:cont, nil}

        nil ->
          raise "Rsolv.Repo process never started after #{max_retries * retry_delay}ms"

        _pid ->
          {:halt, :ok}
      end
    end)

  _pid ->
    :ok
end

# Now ensure we can connect to it
Enum.reduce_while(1..max_retries, nil, fn attempt, _ ->
  try do
    # Try to run a simple query
    Ecto.Adapters.SQL.query!(Rsolv.Repo, "SELECT 1", [])
    {:halt, :ok}
  rescue
    e ->
      if attempt < max_retries do
        Process.sleep(retry_delay)
        {:cont, nil}
      else
        reraise "Failed to connect to Rsolv.Repo after #{max_retries} attempts", __STACKTRACE__
      end
  end
end)

# Setup Ecto Sandbox
Ecto.Adapters.SQL.Sandbox.mode(Rsolv.Repo, :manual)

# Exclude integration tests when using mock parsers
exclude_tags =
  if Application.get_env(:rsolv, :use_mock_parsers, false) do
    [:integration]
  else
    []
  end

ExUnit.start(exclude: exclude_tags)

# Setup Mox Application
Application.ensure_all_started(:mox)

# Ensure FunWithFlags is started for tests
Application.ensure_all_started(:fun_with_flags)

# Replace HTTPoison with mock during testing
Application.put_env(:rsolv, :http_client, Rsolv.HTTPClientMock)

# Configure ConvertKit/Kit.com API from environment variables
# These are set in .envrc or K8s secrets
convertkit_config = [
  api_key: System.get_env("KIT_API_KEY"),
  api_url: System.get_env("KIT_API_URL", "https://api.convertkit.com/v3"),
  form_id: System.get_env("KIT_FORM_ID"),
  ea_tag_id: System.get_env("KIT_EA_TAG_ID")
]

Application.put_env(:rsolv, :convertkit, convertkit_config)

# No longer using AnalyticsStorage - removed
