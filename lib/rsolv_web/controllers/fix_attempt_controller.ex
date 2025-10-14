defmodule RsolvWeb.FixAttemptController do
  use RsolvWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Rsolv.Billing.FixAttempt
  alias Rsolv.Repo
  alias RsolvWeb.Schemas.FixAttempt.{FixAttemptRequest, FixAttemptResponse, ConflictError}
  alias RsolvWeb.Schemas.Error.{ErrorResponse, ValidationError}

  require Logger

  tags ["Fix Attempts"]

  operation(:create,
    summary: "Record a fix attempt",
    description: """
    Record a new security fix attempt for billing and tracking purposes.

    **Authentication Required** - Used by RSOLV GitHub Action.

    **Purpose:**
    This endpoint tracks each vulnerability fix attempt across the SCAN → VALIDATE → MITIGATE workflow.
    Fix attempts are used for:
    - Billing and quota management
    - Success rate analytics
    - Customer usage tracking
    - GitHub Actions workflow monitoring

    **Deduplication:**
    If a fix attempt already exists for the same org/repo/PR combination,
    returns a 409 Conflict error to prevent duplicate billing.

    **Status Values:**
    - `pending`: Fix attempt created, workflow not yet started
    - `in_progress`: Currently applying fixes
    - `completed`: Successfully created PR with fixes
    - `failed`: Fix attempt failed (errors, no fixes needed, etc.)

    **Billing:**
    Fix attempts are typically billed when status transitions to `completed`.
    Failed attempts may be credited or not billed depending on the failure reason.
    """,
    request_body: {
      "Fix attempt details",
      "application/json",
      FixAttemptRequest,
      required: true
    },
    responses: [
      created: {"Fix attempt recorded successfully", "application/json", FixAttemptResponse},
      conflict: {
        "Fix attempt already exists for this PR",
        "application/json",
        ConflictError
      },
      unauthorized: {"Invalid or missing API key", "application/json", ErrorResponse},
      unprocessable_entity: {
        "Validation errors in request body",
        "application/json",
        ValidationError
      }
    ],
    security: [%{"ApiKeyAuth" => []}]
  )

  def create(conn, params) do
    Logger.info("Recording fix attempt for PR #{params["pr_number"]} from #{params["github_org"]}/#{params["repo_name"]}")
    
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
      
      _existing ->
        Logger.warning("Fix attempt already exists for PR #{params["pr_number"]}")
        
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