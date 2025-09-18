defmodule RsolvWeb.Api.V1.PhaseController do
  use RsolvWeb, :controller
  alias Rsolv.Phases
  alias Rsolv.Customers

  plug RsolvWeb.Plugs.ApiAuthentication

  action_fallback RsolvWeb.FallbackController

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
    customer = conn.assigns.customer
    api_key = get_customer_api_key(customer)

    with {:ok, normalized_params} <- normalize_params(params),
         {:ok, result} <- store_phase_data(normalized_params, api_key) do
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

    query = from a in Rsolv.Customers.ApiKey,
      where: a.customer_id == ^customer.id,
      limit: 1

    Rsolv.Repo.one(query)
  end

  defp normalize_params(params) do
    phase = params["phase"] || params[:phase]
    repo = params["repo"] || params[:repo]
    commit_sha = params["commitSha"] || params["commit_sha"] || params[:commitSha] || params[:commit_sha]
    data = params["data"] || params[:data] || %{}
    issue_number = params["issueNumber"] || params["issue_number"] || params[:issueNumber] || params[:issue_number]
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
        {:ok, %{
          phase: phase,
          repo: repo,
          commit_sha: commit_sha,
          data: extract_phase_data(phase, data),
          issue_number: issue_number,
          branch: branch
        }}
    end
  end
  
  defp extract_phase_data("scan", data) do
    # PhaseDataClient sends data.scan for scan phase
    data["scan"] || data[:scan] || data
  end
  
  defp extract_phase_data("validation", data) do
    # PhaseDataClient sends data.validation["issue-#{number}"] for validation phase
    validation_data = data["validation"] || data[:validation] || %{}
    
    # Extract the first issue's validation data (there should only be one)
    case Map.values(validation_data) do
      [issue_data | _] -> issue_data
      [] -> validation_data
    end
  end
  
  defp extract_phase_data("mitigation", data) do
    # PhaseDataClient sends data.mitigation["issue-#{number}"] for mitigation phase
    mitigation_data = data["mitigation"] || data[:mitigation] || %{}
    
    # Extract the first issue's mitigation data (there should only be one)
    case Map.values(mitigation_data) do
      [issue_data | _] -> issue_data
      [] -> mitigation_data
    end
  end
  
  defp extract_phase_data(_, data), do: data
  
  defp store_phase_data(%{phase: "scan"} = params, api_key) do
    Phases.store_scan(%{
      repo: params.repo,
      commit_sha: params.commit_sha,
      branch: params.branch,
      data: params.data
    }, api_key)
  end
  
  defp store_phase_data(%{phase: "validation"} = params, api_key) do
    Phases.store_validation(%{
      repo: params.repo,
      issue_number: params.issue_number,
      commit_sha: params.commit_sha,
      data: params.data
    }, api_key)
  end
  
  defp store_phase_data(%{phase: "mitigation"} = params, api_key) do
    # Extract PR details from the mitigation data
    pr_url = params.data["prUrl"] || params.data["pr_url"]
    pr_number = extract_pr_number(pr_url)
    files_changed = count_changed_files(params.data["fixes"] || params.data[:fixes] || [])
    
    Phases.store_mitigation(%{
      repo: params.repo,
      issue_number: params.issue_number,
      commit_sha: params.commit_sha,
      data: Map.merge(params.data, %{
        "pr_url" => pr_url,
        "pr_number" => pr_number,
        "files_changed" => files_changed
      })
    }, api_key)
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
    api_key = get_customer_api_key(customer)

    with {:ok, validated_params} <- validate_retrieve_params(params),
         {:ok, phase_data} <- Phases.retrieve(
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
        issue_number = case issue do
          num when is_integer(num) -> num
          str when is_binary(str) -> 
            case Integer.parse(str) do
              {num, ""} -> num
              _ -> nil
            end
          _ -> nil
        end
        
        if issue_number do
          {:ok, %{
            repo: repo,
            issue: issue_number,
            commit: commit
          }}
        else
          {:error, :invalid_issue_number}
        end
    end
  end
end