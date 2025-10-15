defmodule RsolvWeb.Admin.DashboardController do
  use RsolvWeb, :controller

  alias RsolvWeb.CustomerAuth
  alias Rsolv.Customers
  alias Rsolv.Repo
  import Ecto.Query

  def index(conn, _params) do
    metrics = gather_metrics()

    render(conn, :index,
      customer: conn.assigns.current_customer,
      metrics: metrics
    )
  end

  defp gather_metrics do
    %{
      total_customers: count_customers(),
      active_api_keys: count_api_keys(),
      system_health: check_system_health(),
      recent_activity: get_recent_activity(),
      request_volume: get_request_volume()
    }
  end

  defp count_customers do
    Repo.aggregate(Customers.Customer, :count, :id)
  end

  defp count_api_keys do
    Repo.aggregate(Customers.ApiKey, :count, :id)
  end

  defp check_system_health do
    %{
      database: check_database_health(),
      overall_status: "Operational"
    }
  end

  defp check_database_health do
    try do
      Repo.query!("SELECT 1")
      "Operational"
    rescue
      _ -> "Error"
    end
  end

  defp get_recent_activity do
    # Get recent API key creations with preloaded customer
    recent_keys =
      from(k in Customers.ApiKey,
        order_by: [desc: k.inserted_at],
        limit: 5,
        preload: [:customer]
      )
      |> Repo.all()
      |> Enum.map(fn key ->
        %{
          type: "api_key_created",
          description: "#{key.customer.email} created API key #{key.name}",
          customer_email: key.customer.email,
          timestamp: key.inserted_at
        }
      end)

    # Get recent customer registrations
    recent_customers =
      from(c in Customers.Customer,
        order_by: [desc: c.inserted_at],
        limit: 5
      )
      |> Repo.all()
      |> Enum.map(fn customer ->
        %{
          type: "customer_created",
          description: "#{customer.email} registered",
          customer_email: customer.email,
          timestamp: customer.inserted_at
        }
      end)

    # Combine and sort by timestamp
    (recent_keys ++ recent_customers)
    |> Enum.sort_by(& &1.timestamp, {:desc, NaiveDateTime})
    |> Enum.take(10)
  end

  defp get_request_volume do
    # For now, return placeholder data
    # In production, this would query metrics/analytics tables
    %{
      today: 0,
      this_week: 0,
      this_month: 0
    }
  end

  def logout(conn, _params) do
    CustomerAuth.log_out_customer(conn)
  end
end
