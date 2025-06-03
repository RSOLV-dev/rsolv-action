defmodule RSOLVWeb.FixAttemptController do
  use RSOLVWeb, :controller
  alias RsolvApi.Billing.FixAttempt
  alias RsolvApi.Repo
  import Ecto.Query
  require Logger

  def create(conn, params) do
    # Debug instrumentation for production troubleshooting
    Logger.info("=== FIX ATTEMPT DEBUG START ===")
    Logger.info("Raw params: #{inspect(params)}")
    Logger.info("Conn body_params: #{inspect(conn.body_params)}")
    Logger.info("Conn params: #{inspect(conn.params)}")
    Logger.info("Content-Type: #{inspect(get_req_header(conn, "content-type"))}")
    Logger.info("Content-Length: #{inspect(get_req_header(conn, "content-length"))}")
    Logger.info("Authorization: #{inspect(get_req_header(conn, "authorization"))}")
    Logger.info("Request method: #{conn.method}")
    Logger.info("Request path: #{conn.request_path}")
    Logger.info("Request body: #{inspect(conn.assigns[:raw_body])}")
    Logger.info("Has been read?: #{conn.assigns[:parsed] || false}")
    Logger.info("Adapter: #{inspect(conn.adapter)}")
    Logger.info("=== FIX ATTEMPT DEBUG END ===")
    
    Logger.info("Recording fix attempt for PR #{params["pr_number"]}")
    
    # Set default status if not provided
    attrs = Map.put(params, "status", params["status"] || "pending")
    
    # Check for existing fix attempt to prevent duplicates
    case find_existing_fix_attempt(attrs) do
      nil ->
        case create_fix_attempt(attrs) do
          {:ok, fix_attempt} ->
            Logger.info("Fix attempt recorded successfully: #{fix_attempt.id}")
            
            conn
            |> put_status(:created)
            |> json(%{
              id: fix_attempt.id,
              status: fix_attempt.status,
              github_org: fix_attempt.github_org,
              repo_name: fix_attempt.repo_name,
              pr_number: fix_attempt.pr_number,
              billing_status: fix_attempt.billing_status
            })
            
          {:error, changeset} ->
            Logger.error("Failed to create fix attempt: #{inspect(changeset.errors)}")
            
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{errors: format_changeset_errors(changeset)})
        end
      
      existing ->
        Logger.warn("Fix attempt already exists for PR #{params["pr_number"]}")
        
        conn
        |> put_status(:conflict)
        |> json(%{error: "Fix attempt already exists for this PR"})
    end
  end
  
  defp find_existing_fix_attempt(attrs) do
    github_org = attrs["github_org"]
    repo_name = attrs["repo_name"]
    pr_number = attrs["pr_number"]
    
    if github_org && repo_name && pr_number do
      Repo.get_by(FixAttempt,
        github_org: github_org,
        repo_name: repo_name,
        pr_number: pr_number
      )
    else
      nil
    end
  end
  
  defp create_fix_attempt(attrs) do
    %FixAttempt{}
    |> FixAttempt.changeset(attrs)
    |> Repo.insert()
  end
  
  defp format_changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end