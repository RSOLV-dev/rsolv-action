# Ensure the application is started
{:ok, _} = Application.ensure_all_started(:rsolv)

# Wait for the repo to be ready
max_retries = 30
retry_delay = 100 # milliseconds

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
    _ ->
      if attempt < max_retries do
        Process.sleep(retry_delay)
        {:cont, nil}
      else
        raise "Failed to connect to Rsolv.Repo after #{max_retries} attempts"
      end
  end
end)

# Setup Ecto Sandbox
Ecto.Adapters.SQL.Sandbox.mode(Rsolv.Repo, :manual)

# Exclude integration tests when using mock parsers
exclude_tags = if Application.get_env(:rsolv, :use_mock_parsers, false) do
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

# No longer using AnalyticsStorage - removed
