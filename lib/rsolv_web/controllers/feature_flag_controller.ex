defmodule RsolvWeb.FeatureFlagController do
  use RsolvWeb, :controller

  alias Rsolv.FeatureFlags
  alias Rsolv.Accounts

  action_fallback RsolvWeb.FallbackController

  @doc """
  GET /api/v1/admin/feature-flags
  List all feature flags and their current values
  """
  def index(conn, _params) do
    with {:ok, _admin} <- authenticate_admin(conn) do
      flags = FeatureFlags.all_flags()

      json(conn, %{
        feature_flags: flags,
        environment_overrides: get_environment_overrides()
      })
    end
  end

  @doc """
  GET /api/v1/admin/feature-flags/:flag_name
  Get a specific feature flag's status
  """
  def show(conn, %{"flag_name" => flag_name}) do
    with {:ok, _admin} <- authenticate_admin(conn) do
      enabled = FeatureFlags.enabled?(flag_name)

      json(conn, %{
        flag_name: flag_name,
        enabled: enabled,
        source: get_flag_source(flag_name)
      })
    end
  end

  # Private functions

  defp authenticate_admin(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> api_key] ->
        case Accounts.get_customer_by_api_key(api_key) do
          %{id: "internal"} = admin ->
            {:ok, admin}

          %{id: "master"} = admin ->
            {:ok, admin}

          %{email: email} = admin when is_binary(email) ->
            if String.ends_with?(email, "@rsolv.dev") do
              {:ok, admin}
            else
              conn
              |> put_status(:forbidden)
              |> json(%{error: "Admin access required"})
              |> halt()
            end

          _ ->
            conn
            |> put_status(:forbidden)
            |> json(%{error: "Admin access required"})
            |> halt()
        end

      _ ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "API key required"})
        |> halt()
    end
  end

  defp get_environment_overrides do
    System.get_env()
    |> Enum.filter(fn {key, _value} -> String.starts_with?(key, "RSOLV_FLAG_") end)
    |> Enum.map(fn {key, value} ->
      flag_name =
        key
        |> String.replace("RSOLV_FLAG_", "")
        |> String.downcase()
        |> String.replace("_", ".")

      {flag_name, value}
    end)
    |> Map.new()
  end

  defp get_flag_source(flag_name) do
    env_key = "RSOLV_FLAG_" <> String.upcase(String.replace(flag_name, ".", "_"))

    cond do
      System.get_env(env_key) -> "environment"
      Application.get_env(:rsolv, :feature_flags, %{})[flag_name] -> "config"
      true -> "default"
    end
  end
end
