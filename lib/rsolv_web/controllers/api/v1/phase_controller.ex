defmodule RsolvWeb.Api.V1.PhaseController do
  use RsolvWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Rsolv.Phases
  alias RsolvWeb.Schemas.Phase.{PhaseStoreRequest, PhaseStoreResponse, PhaseRetrieveResponse}
  alias RsolvWeb.Schemas.Error.ErrorResponse

  plug RsolvWeb.Plugs.ApiAuthentication
  plug OpenApiSpex.Plug.CastAndValidate, json_render_error_v2: true

  action_fallback RsolvWeb.FallbackController

  tags(["Phases"])

  operation(:store,
    summary: "Store phase execution data",
    description: """
    Stores data from RSOLV GitHub Action workflow phases (scan, validation, mitigation).

    **Phases:**
    - `scan`: Initial vulnerability detection results
    - `validation`: RED/GREEN/REFACTOR test generation results
    - `mitigation`: Final fix and PR creation results

    **Data Flow:**
    1. SCAN phase stores findings and creates GitHub issues
    2. VALIDATION phase stores test generation results (linked by issue number)
    3. MITIGATION phase stores fix application and PR details (linked by issue number)

    **Requirements:**
    - `issueNumber` required for validation and mitigation phases
    - `branch` optional for scan phase
    - Data structure varies by phase type

    **Use Case:**
    Enables tracking of multi-phase fix attempts across workflow runs.
    """,
    request_body: {"Phase data storage request", "application/json", PhaseStoreRequest},
    responses: [
      ok: {"Phase data stored successfully", "application/json", PhaseStoreResponse},
      bad_request: {"Invalid request parameters", "application/json", ErrorResponse},
      unauthorized: {"Invalid API key", "application/json", ErrorResponse},
      internal_server_error: {"Failed to store phase data", "application/json", ErrorResponse}
    ],
    security: [%{"ApiKeyAuth" => []}]
  )

  @doc """
  Store phase execution data.

  Expects JSON body with:
  - phase: "scan" | "validation" | "mitigation"
  - repo: "owner/name" format
  - commitSha: Git commit SHA
  - data: Phase-specific data object
  - issueNumber: Required for validation and mitigation phases
  - branch: Optional, for scan phase
  """
  def store(conn, params) do
    # Debug logging to see what params are actually received
    require Logger
    IO.puts("[PhaseController] Received params:")
    IO.inspect(params, label: "[PhaseController] Full params", pretty: true, limit: :infinity)
    IO.inspect(Map.keys(params), label: "[PhaseController] Params keys")
    Logger.info("[PhaseController] Received params: #{inspect(params, pretty: true)}")
    Logger.info("[PhaseController] Params keys: #{inspect(Map.keys(params))}")

    customer = conn.assigns.customer
    # Use the actual API key that was used for authentication
    api_key = conn.assigns.api_key || get_customer_api_key(customer)

    start_time = System.monotonic_time()

    with {:ok, normalized_params} <- normalize_params(params),
         {:ok, result} <- store_phase_data(normalized_params, api_key) do

      # Emit telemetry event for metrics (RFC-060 Phase 6)
      duration = System.monotonic_time() - start_time
      emit_phase_telemetry(normalized_params, duration, "success")

      json(conn, %{
        success: true,
        id: result.id,
        phase: normalized_params.phase
      })
    end
  end

  defp get_customer_api_key(customer) do
    # Get the API key that was used for authentication
    # We need to look it up again to get the full ApiKey struct for phase storage
    # This is a temporary workaround - ideally the plug should store the full api_key struct
    import Ecto.Query

    query =
      from a in Rsolv.Customers.ApiKey,
        where: a.customer_id == ^customer.id,
        limit: 1

    Rsolv.Repo.one(query)
  end

  defp normalize_params(params) do
    phase = params["phase"] || params[:phase]
    repo = params["repo"] || params[:repo]

    commit_sha =
      params["commitSha"] || params["commit_sha"] || params[:commitSha] || params[:commit_sha]

    data = params["data"] || params[:data] || %{}

    issue_number =
      params["issueNumber"] || params["issue_number"] || params[:issueNumber] ||
        params[:issue_number]

    branch = params["branch"] || params[:branch]

    # Validate required fields
    cond do
      is_nil(phase) ->
        {:error, :phase_required}

      is_nil(repo) ->
        {:error, :repo_required}

      is_nil(commit_sha) ->
        {:error, :commit_sha_required}

      phase in ["validation", "mitigation"] and is_nil(issue_number) ->
        {:error, :issue_number_required}

      true ->
        {:ok,
         %{
           phase: phase,
           repo: repo,
           commit_sha: commit_sha,
           data: extract_phase_data(phase, data),
           issue_number: issue_number,
           branch: branch
         }}
    end
  end

  # All phases now use the same simple format: data is sent directly, not wrapped
  # Example: {phase: "validation", data: {branchName: "...", validated: true}, ...}
  defp extract_phase_data(_phase, data), do: data

  defp store_phase_data(%{phase: "scan"} = params, api_key) do
    Phases.store_scan(
      %{
        repo: params.repo,
        commit_sha: params.commit_sha,
        branch: params.branch,
        data: params.data
      },
      api_key
    )
  end

  defp store_phase_data(%{phase: "validation"} = params, api_key) do
    Phases.store_validation(
      %{
        repo: params.repo,
        issue_number: params.issue_number,
        commit_sha: params.commit_sha,
        data: params.data
      },
      api_key
    )
  end

  defp store_phase_data(%{phase: "mitigation"} = params, api_key) do
    # Extract PR details from the mitigation data
    pr_url = params.data["prUrl"] || params.data["pr_url"]
    pr_number = extract_pr_number(pr_url)
    files_changed = count_changed_files(params.data["fixes"] || params.data[:fixes] || [])

    Phases.store_mitigation(
      %{
        repo: params.repo,
        issue_number: params.issue_number,
        commit_sha: params.commit_sha,
        data:
          Map.merge(params.data, %{
            "pr_url" => pr_url,
            "pr_number" => pr_number,
            "files_changed" => files_changed
          })
      },
      api_key
    )
  end

  defp store_phase_data(_, _), do: {:error, :invalid_phase}

  defp extract_pr_number(nil), do: nil

  defp extract_pr_number(pr_url) when is_binary(pr_url) do
    # Extract PR number from URL like "https://github.com/owner/repo/pull/123"
    case Regex.run(~r/\/pull\/(\d+)/, pr_url) do
      [_, number] -> String.to_integer(number)
      _ -> nil
    end
  end

  defp extract_pr_number(_), do: nil

  defp count_changed_files(fixes) when is_list(fixes) do
    fixes
    |> Enum.map(&(&1["file"] || &1[:file]))
    |> Enum.uniq()
    |> Enum.count()
  end

  defp count_changed_files(_), do: 0

  operation(:retrieve,
    summary: "Retrieve accumulated phase data",
    description: """
    Retrieves accumulated data from all three workflow phases for a specific fix attempt.

    **Lookup Keys:**
    - Repository (owner/name format)
    - GitHub issue number
    - Commit SHA

    **Returns:**
    Merged data from scan, validation, and mitigation phases, allowing the action
    to access previous phase results in later phases.

    **Example Use Case:**
    MITIGATION phase retrieves VALIDATION phase test files to verify fixes pass tests.
    """,
    parameters: [
      repo: [
        in: :query,
        description: "Repository in owner/name format",
        type: :string,
        required: true,
        example: "octocat/hello-world"
      ],
      issue: [
        in: :query,
        description: "GitHub issue number",
        type: :integer,
        required: true,
        example: 42
      ],
      commit: [
        in: :query,
        description: "Git commit SHA",
        type: :string,
        required: true,
        example: "abc123def456"
      ]
    ],
    responses: [
      ok: {"Phase data retrieved successfully", "application/json", PhaseRetrieveResponse},
      bad_request: {"Invalid query parameters", "application/json", ErrorResponse},
      unauthorized: {"Invalid API key", "application/json", ErrorResponse},
      not_found: {"Phase data not found", "application/json", ErrorResponse}
    ],
    security: [%{"ApiKeyAuth" => []}]
  )

  @doc """
  Retrieve phase execution data.

  Expects query parameters:
  - repo: "owner/name" format
  - issue: Issue number
  - commit: Git commit SHA

  Returns accumulated phase data from all three phases.
  """
  def retrieve(conn, params) do
    customer = conn.assigns.customer
    # Use the actual API key that was used for authentication
    api_key = conn.assigns.api_key || get_customer_api_key(customer)

    with {:ok, validated_params} <- validate_retrieve_params(params),
         {:ok, phase_data} <-
           Phases.retrieve(
             validated_params.repo,
             validated_params.issue,
             validated_params.commit,
             api_key
           ) do
      json(conn, phase_data)
    end
  end

  defp validate_retrieve_params(params) do
    repo = params["repo"] || params[:repo]
    issue = params["issue"] || params[:issue]
    commit = params["commit"] || params[:commit]

    cond do
      is_nil(repo) ->
        {:error, :repo_required}

      is_nil(issue) ->
        {:error, :issue_required}

      is_nil(commit) ->
        {:error, :commit_required}

      true ->
        # Convert issue to integer if it's a string
        issue_number =
          case issue do
            num when is_integer(num) ->
              num

            str when is_binary(str) ->
              case Integer.parse(str) do
                {num, ""} -> num
                _ -> nil
              end

            _ ->
              nil
          end

        if issue_number do
          {:ok,
           %{
             repo: repo,
             issue: issue_number,
             commit: commit
           }}
        else
          {:error, :invalid_issue_number}
        end
    end
  end

  # Emit telemetry events for Prometheus metrics (RFC-060 Phase 6)
  defp emit_phase_telemetry(params, duration, status) do
    case params.phase do
      "validation" ->
        # Emit validation completion event
        :telemetry.execute(
          [:rsolv, :validation, :complete],
          %{duration: duration},
          %{
            repo: params.repo,
            status: status,
            language: extract_language_from_data(params.data),
            framework: extract_framework_from_data(params.data)
          }
        )

        # If test was generated, emit test generation event
        if params.data && Map.get(params.data, "redTests") do
          :telemetry.execute(
            [:rsolv, :validation, :test_generated],
            %{},
            %{
              repo: params.repo,
              language: extract_language_from_data(params.data),
              framework: extract_framework_from_data(params.data)
            }
          )
        end

      "mitigation" ->
        # Emit mitigation completion event
        :telemetry.execute(
          [:rsolv, :mitigation, :complete],
          %{duration: duration},
          %{
            repo: params.repo,
            status: status,
            language: extract_language_from_data(params.data),
            framework: extract_framework_from_data(params.data)
          }
        )

        # If trust score is available, emit trust score event
        if params.data && Map.get(params.data, "trustScore") do
          :telemetry.execute(
            [:rsolv, :mitigation, :trust_score],
            %{trust_score: Map.get(params.data, "trustScore")},
            %{
              repo: params.repo,
              language: extract_language_from_data(params.data),
              framework: extract_framework_from_data(params.data)
            }
          )
        end

      _ ->
        # No metrics for scan phase yet
        :ok
    end
  end

  defp extract_language_from_data(data) when is_map(data) do
    Map.get(data, "language") || Map.get(data, :language) || "unknown"
  end
  defp extract_language_from_data(_), do: "unknown"

  defp extract_framework_from_data(data) when is_map(data) do
    Map.get(data, "framework") || Map.get(data, :framework) || "none"
  end
  defp extract_framework_from_data(_), do: "none"
end
