defmodule Rsolv.Phases do
  @moduledoc """
  Main context for phase data storage and retrieval.
  Handles storing scan, validation, and mitigation execution data.
  """
  
  alias Rsolv.Repo
  alias Rsolv.Phases.{Repository, Repositories, ScanExecution, ValidationExecution, MitigationExecution}
  alias Rsolv.Customers.{Customer, ApiKey, ForgeAccount}
  
  @doc """
  Stores scan phase execution data.
  
  ## Parameters
    - attrs: Map containing repo, commit_sha, branch, data, started_at, completed_at
    - api_key: The API key used for authentication
    
  ## Returns
    - {:ok, scan_execution} on success
    - {:error, changeset} on validation failure
    - {:error, :unauthorized} if customer doesn't have access to namespace
  """
  def store_scan(attrs, %ApiKey{} = api_key) do
    with {:ok, customer} <- get_customer_from_api_key(api_key),
         {:ok, repo_attrs} <- parse_repo_string(attrs[:repo] || attrs["repo"]),
         {:ok, repository} <- Repositories.find_or_create(repo_attrs, customer) do
      case create_scan_execution(attrs, repository, api_key) do
        {:ok, scan} -> {:ok, Repo.preload(scan, :repository)}
        {:error, changeset} -> {:error, changeset}
      end
    end
  end
  
  @doc """
  Stores validation phase execution data.
  
  ## Parameters
    - attrs: Map containing repo, issue_number, commit_sha, data
    - api_key: The API key used for authentication
    
  ## Returns
    - {:ok, validation_execution} on success
    - {:error, changeset} on validation failure
    - {:error, :unauthorized} if customer doesn't have access to namespace
  """
  def store_validation(attrs, %ApiKey{} = api_key) do
    with {:ok, customer} <- get_customer_from_api_key(api_key),
         {:ok, repo_attrs} <- parse_repo_string(attrs[:repo] || attrs["repo"]),
         {:ok, repository} <- Repositories.find_or_create(repo_attrs, customer),
         {:ok, validation} <- create_validation_execution(attrs, repository, api_key) do
      {:ok, Repo.preload(validation, :repository)}
    end
  end
  
  @doc """
  Stores mitigation phase execution data.
  
  ## Parameters
    - attrs: Map containing repo, issue_number, commit_sha, data (with pr_url, pr_number, files_changed)
    - api_key: The API key used for authentication
    
  ## Returns
    - {:ok, mitigation_execution} on success
    - {:error, changeset} on validation failure
    - {:error, :unauthorized} if customer doesn't have access to namespace
  """
  def store_mitigation(attrs, %ApiKey{} = api_key) do
    with {:ok, customer} <- get_customer_from_api_key(api_key),
         {:ok, repo_attrs} <- parse_repo_string(attrs[:repo] || attrs["repo"]),
         {:ok, repository} <- Repositories.find_or_create(repo_attrs, customer),
         {:ok, mitigation} <- create_mitigation_execution(attrs, repository, api_key) do
      {:ok, Repo.preload(mitigation, :repository)}
    end
  end
  
  # Private functions
  
  defp get_customer_from_api_key(%ApiKey{customer_id: customer_id}) do
    customer = Repo.get(Customer, customer_id)
    if customer, do: {:ok, customer}, else: {:error, :customer_not_found}
  end
  
  defp verify_namespace_ownership(customer, repo_attrs) do
    import Ecto.Query
    
    query = from fa in ForgeAccount,
      where: fa.customer_id == ^customer.id,
      where: fa.forge_type == ^repo_attrs.forge_type,
      where: fa.namespace == ^repo_attrs.namespace
    
    case Repo.one(query) do
      nil ->
        {:error, :unauthorized}
      %ForgeAccount{verified_at: nil} ->
        {:error, :forge_not_verified}
      forge_account ->
        {:ok, forge_account}
    end
  end
  
  defp parse_repo_string(nil), do: {:error, :repo_required}
  defp parse_repo_string(repo_string) do
    case String.split(repo_string, "/", parts: 2) do
      [namespace, name] ->
        {:ok, %{
          forge_type: :github,  # Default to GitHub for now
          namespace: namespace,
          name: name
        }}
      _ ->
        {:error, :invalid_repo_format}
    end
  end
  
  defp create_scan_execution(attrs, repository, api_key) do
    data = attrs[:data] || attrs["data"] || %{}
    # Convert atom keys to string keys for consistent JSONB storage
    data = stringify_keys(data)
    vulnerabilities = data["vulnerabilities"] || []
    
    changeset = %ScanExecution{}
    |> ScanExecution.changeset(%{
      repository_id: repository.id,
      commit_sha: attrs[:commit_sha] || attrs["commit_sha"],
      branch: attrs[:branch] || attrs["branch"],
      status: :completed,
      vulnerabilities_count: length(vulnerabilities),
      data: data,
      started_at: attrs[:started_at] || attrs["started_at"] || DateTime.utc_now(),
      completed_at: attrs[:completed_at] || attrs["completed_at"] || DateTime.utc_now(),
      api_key_id: api_key.id
    })
    
    case Repo.insert(changeset) do
      {:ok, scan} -> {:ok, scan}
      {:error, changeset} -> {:error, changeset}
    end
  end
  
  defp create_validation_execution(attrs, repository, api_key) do
    data = attrs[:data] || attrs["data"] || %{}
    # Convert atom keys to string keys for consistent JSONB storage
    data = stringify_keys(data)
    vulnerabilities = data["vulnerabilities"] || []
    validated = data["validated"] || false
    
    %ValidationExecution{}
    |> ValidationExecution.changeset(%{
      repository_id: repository.id,
      issue_number: attrs[:issue_number] || attrs["issue_number"],
      commit_sha: attrs[:commit_sha] || attrs["commit_sha"],
      status: :completed,
      validated: validated,
      vulnerabilities_found: length(vulnerabilities),
      data: data,
      started_at: attrs[:started_at] || attrs["started_at"] || DateTime.utc_now(),
      completed_at: attrs[:completed_at] || attrs["completed_at"] || DateTime.utc_now(),
      api_key_id: api_key.id
    })
    |> Repo.insert()
  end
  
  defp create_mitigation_execution(attrs, repository, api_key) do
    data = attrs[:data] || attrs["data"] || %{}
    # Convert atom keys to string keys for consistent JSONB storage
    data = stringify_keys(data)
    
    %MitigationExecution{}
    |> MitigationExecution.changeset(%{
      repository_id: repository.id,
      issue_number: attrs[:issue_number] || attrs["issue_number"],
      commit_sha: attrs[:commit_sha] || attrs["commit_sha"],
      status: :completed,
      pr_url: data["pr_url"],
      pr_number: data["pr_number"],
      files_changed: data["files_changed"],
      data: data,
      started_at: attrs[:started_at] || attrs["started_at"] || DateTime.utc_now(),
      completed_at: attrs[:completed_at] || attrs["completed_at"] || DateTime.utc_now(),
      api_key_id: api_key.id
    })
    |> Repo.insert()
  end
  
  # Helper to convert atom keys to string keys recursively
  defp stringify_keys(map) when is_map(map) and not is_struct(map) do
    map
    |> Enum.map(fn
      {k, v} when is_atom(k) -> {Atom.to_string(k), stringify_keys(v)}
      {k, v} -> {k, stringify_keys(v)}
    end)
    |> Enum.into(%{})
  end
  defp stringify_keys(list) when is_list(list) do
    Enum.map(list, &stringify_keys/1)
  end
  defp stringify_keys(value), do: value
  
  @doc """
  Retrieves all phase data for a repository/issue/commit combination.
  
  Returns a map with keys for each phase that has data:
  - "scan" => scan execution data
  - "validation" => validation data keyed by issue
  - "mitigation" => mitigation data keyed by issue
  """
  def retrieve(repo_string, issue_number, commit_sha, %ApiKey{} = api_key) do
    with {:ok, customer} <- get_customer_from_api_key(api_key),
         {:ok, repo_attrs} <- parse_repo_string(repo_string),
         {:ok, _forge_account} <- verify_namespace_ownership(customer, repo_attrs),
         {:ok, repository} <- get_repository(repo_attrs) do
      
      # If no repository exists, return empty phase data
      if is_nil(repository) do
        {:ok, %{}}
      else
        phase_data = %{}
        
        # Get scan data for this commit
        phase_data = case get_scan_execution(repository.id, commit_sha) do
          nil -> phase_data
          scan -> Map.put(phase_data, "scan", scan.data)
        end
        
        # Get validation data for this issue
        phase_data = case get_validation_execution(repository.id, issue_number) do
          nil -> phase_data
          validation -> 
            validation_data = %{
              "issue-#{issue_number}" => validation.data
            }
            Map.put(phase_data, "validation", validation_data)
        end
        
        # Get mitigation data for this issue
        phase_data = case get_mitigation_execution(repository.id, issue_number) do
          nil -> phase_data
          mitigation ->
            mitigation_data = %{
              "issue-#{issue_number}" => mitigation.data
            }
            Map.put(phase_data, "mitigation", mitigation_data)
        end
        
        {:ok, phase_data}
      end
    end
  end
  
  defp get_repository(repo_attrs) do
    case Repo.get_by(Repository,
      forge_type: repo_attrs.forge_type,
      namespace: repo_attrs.namespace,
      name: repo_attrs.name
    ) do
      nil -> {:ok, nil}  # No repository means no data to retrieve
      repo -> {:ok, repo}
    end
  end
  
  defp get_scan_execution(nil, _), do: nil
  defp get_scan_execution(repository_id, commit_sha) do
    # Get the most recent scan for this commit
    # Multiple scans can exist if the same commit was scanned multiple times
    import Ecto.Query
    
    ScanExecution
    |> where([s], s.repository_id == ^repository_id and s.commit_sha == ^commit_sha)
    |> order_by([s], desc: s.inserted_at)
    |> limit(1)
    |> Repo.one()
  end
  
  defp get_validation_execution(nil, _), do: nil
  defp get_validation_execution(repository_id, issue_number) do
    # Get the most recent validation for this issue
    import Ecto.Query
    
    ValidationExecution
    |> where([v], v.repository_id == ^repository_id and v.issue_number == ^issue_number)
    |> order_by([v], desc: v.inserted_at)
    |> limit(1)
    |> Repo.one()
  end
  
  defp get_mitigation_execution(nil, _), do: nil
  defp get_mitigation_execution(repository_id, issue_number) do
    # Get the most recent mitigation for this issue
    import Ecto.Query
    
    MitigationExecution
    |> where([m], m.repository_id == ^repository_id and m.issue_number == ^issue_number)
    |> order_by([m], desc: m.inserted_at)
    |> limit(1)
    |> Repo.one()
  end
end