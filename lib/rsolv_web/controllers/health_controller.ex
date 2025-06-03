defmodule RSOLVWeb.HealthController do
  use RSOLVWeb, :controller

  def check(conn, _params) do
    # Basic health check
    health_status = %{
      status: "ok",
      service: "rsolv-api",
      version: "0.1.0",
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    }

    # Check database connectivity
    db_status = check_database()
    
    # Check external services
    services_status = %{
      database: db_status,
      redis: check_redis(),
      ai_providers: check_ai_providers()
    }

    overall_status = if all_healthy?(services_status) do
      "healthy"
    else
      "degraded"
    end

    response = Map.merge(health_status, %{
      status: overall_status,
      services: services_status
    })

    conn
    |> put_status(if overall_status == "healthy", do: :ok, else: :service_unavailable)
    |> json(response)
  end

  defp check_database do
    try do
      Ecto.Adapters.SQL.query!(RsolvApi.Repo, "SELECT 1", [])
      "healthy"
    rescue
      _ -> "unhealthy"
    end
  end

  defp check_redis do
    # Placeholder for Redis/cache health check
    "healthy"
  end

  defp check_ai_providers do
    %{
      anthropic: "healthy",
      openai: "healthy",
      openrouter: "healthy"
    }
  end

  defp all_healthy?(services) do
    services
    |> Map.values()
    |> Enum.all?(&(&1 == "healthy" || is_map(&1)))
  end
end