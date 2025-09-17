defmodule RsolvWeb.CredentialControllerDemo do
  @moduledoc """
  Demo/Local mode support for credential vending.
  This module provides a way to handle credential exchange without full GitHub Action context.
  """

  import Plug.Conn
  require Logger

  @doc """
  Check if we're in demo mode and handle appropriately
  """
  def handle_demo_mode(params, conn) do
    # Check for demo mode indicators
    is_demo = params["demo_mode"] == true ||
              params["forge_type"] == "local" ||
              get_req_header(conn, "x-rsolv-demo-mode") != []

    if is_demo do
      {:ok, enrich_params_for_demo(params)}
    else
      {:ok, params}
    end
  end

  @doc """
  Enrich params with sensible defaults for demo/local testing
  """
  def enrich_params_for_demo(params) do
    # Auto-populate missing fields for demo mode
    params
    |> Map.put_new("forge_account_id", get_forge_account_from_context(params))
    |> Map.put_new("repository", get_repository_from_context(params))
    |> Map.put_new("issue_number", params["issue_number"] || 1)
    |> Map.put_new("providers", ["anthropic"])  # Default to Anthropic for demos
  end

  defp get_forge_account_from_context(params) do
    # Try to infer from various sources
    cond do
      params["forge_account_id"] -> params["forge_account_id"]
      params["github_actor"] -> "github-#{params["github_actor"]}"
      params["repository"] && String.contains?(params["repository"], "/") ->
        params["repository"] |> String.split("/") |> List.first() |> then(&"github-#{&1}")
      true -> "demo-local-#{:os.system_time(:second)}"
    end
  end

  defp get_repository_from_context(params) do
    cond do
      params["repository"] -> params["repository"]
      params["github_repository"] -> params["github_repository"]
      true -> "demo/nodegoat-vulnerability-demo"
    end
  end

  @doc """
  Auto-create or fetch forge account for demo purposes
  """
  def ensure_demo_forge_account(forge_account_id) do
    # Check if this forge account exists, create if not
    case Rsolv.Forges.get_forge_account_by_external_id(forge_account_id) do
      nil ->
        # Create a demo forge account
        attrs = %{
          external_id: forge_account_id,
          provider: "github",
          name: "Demo Account (#{forge_account_id})",
          metadata: %{
            "demo" => true,
            "created_at" => DateTime.utc_now()
          }
        }

        case Rsolv.Forges.create_forge_account(attrs) do
          {:ok, forge_account} ->
            Logger.info("Created demo forge account: #{forge_account_id}")
            {:ok, forge_account}
          error ->
            Logger.error("Failed to create demo forge account: #{inspect(error)}")
            {:error, :forge_account_creation_failed}
        end

      forge_account ->
        {:ok, forge_account}
    end
  end
end