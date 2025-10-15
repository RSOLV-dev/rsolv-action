defmodule Rsolv.Phases.Repositories do
  @moduledoc """
  Context for managing repositories with auto-creation and access control.
  """

  import Ecto.Query
  alias Rsolv.Repo
  alias Rsolv.Phases.Repository
  alias Rsolv.Customers.{Customer, ForgeAccount}

  @doc """
  Finds or creates a repository, ensuring the customer has access to the namespace.

  ## Parameters
    - attrs: Map with :forge_type, :namespace, and :name
    - customer: The customer attempting to access the repository
    
  ## Returns
    - {:ok, repository} on success
    - {:error, :unauthorized} if customer doesn't own the namespace
    - {:error, :forge_not_verified} if the forge account is not verified
  """
  def find_or_create(attrs, %Customer{} = customer) do
    forge_type = parse_forge_type(attrs[:forge_type] || attrs["forge_type"])
    namespace = attrs[:namespace] || attrs["namespace"]
    name = attrs[:name] || attrs["name"]

    # Check if customer has access to this namespace
    with {:ok, forge_account} <- verify_namespace_access(customer, forge_type, namespace),
         {:ok, repository} <-
           find_or_create_repository(forge_account, forge_type, namespace, name, customer) do
      {:ok, repository}
    end
  end

  defp parse_forge_type("github"), do: :github
  defp parse_forge_type(:github), do: :github
  # Future: Add gitlab support
  defp parse_forge_type(_), do: :github

  defp verify_namespace_access(customer, forge_type, namespace) do
    query =
      from fa in ForgeAccount,
        where: fa.customer_id == ^customer.id,
        where: fa.forge_type == ^forge_type,
        where: fa.namespace == ^namespace

    case Repo.one(query) do
      nil ->
        {:error, :unauthorized}

      %ForgeAccount{verified_at: nil} ->
        {:error, :forge_not_verified}

      forge_account ->
        {:ok, forge_account}
    end
  end

  defp find_or_create_repository(_forge_account, forge_type, namespace, name, customer) do
    full_path = "#{namespace}/#{name}"

    case get_repository(forge_type, namespace, name) do
      nil ->
        create_repository(forge_type, namespace, name, full_path, customer.id)

      repository ->
        # Update last_activity_at
        update_last_activity(repository)
    end
  end

  defp get_repository(forge_type, namespace, name) do
    Repo.get_by(Repository,
      forge_type: forge_type,
      namespace: namespace,
      name: name
    )
  end

  defp create_repository(forge_type, namespace, name, full_path, customer_id) do
    %Repository{}
    |> Repository.changeset(%{
      forge_type: forge_type,
      namespace: namespace,
      name: name,
      full_path: full_path,
      customer_id: customer_id,
      first_seen_at: DateTime.utc_now(),
      last_activity_at: DateTime.utc_now()
    })
    |> Repo.insert()
  end

  defp update_last_activity(repository) do
    repository
    |> Repository.changeset(%{
      last_activity_at: DateTime.utc_now()
    })
    |> Repo.update()
  end
end
