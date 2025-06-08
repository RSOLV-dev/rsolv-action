defmodule RSOLV.Accounts do
  @moduledoc """
  The Accounts context for managing customers and API keys.
  """

  import Ecto.Query, warn: false
  alias RsolvApi.Repo
  alias RSOLV.Accounts.Customer

  @doc """
  Gets a customer by API key.
  
  Returns nil if no customer found.
  """
  def get_customer_by_api_key(api_key) when is_binary(api_key) do
    Repo.get_by(Customer, api_key: api_key, is_active: true)
  end

  def get_customer_by_api_key(_), do: nil

  @doc """
  Creates a customer.
  """
  def create_customer(attrs \\ %{}) do
    %Customer{}
    |> Customer.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Lists all customers.
  """
  def list_customers do
    Repo.all(Customer)
  end

  @doc """
  Gets a single customer.
  """
  def get_customer!(id), do: Repo.get!(Customer, id)
end