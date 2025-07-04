defmodule Rsolv.Customers do
  @moduledoc """
  The Customers context.
  """

  import Ecto.Query, warn: false
  alias Rsolv.Repo

  alias Rsolv.Customers.{Customer, ApiKey}

  @doc """
  Returns the list of customers.

  ## Examples

      iex> list_customers()
      [%Customer{}, ...]

  """
  def list_customers do
    Repo.all(Customer)
  end

  @doc """
  Gets a single customer.

  Raises `Ecto.NoResultsError` if the Customer does not exist.

  ## Examples

      iex> get_customer!(123)
      %Customer{}

      iex> get_customer!(456)
      ** (Ecto.NoResultsError)

  """
  def get_customer!(id), do: Repo.get!(Customer, id)

  @doc """
  Gets a customer by API key.
  """
  def get_customer_by_api_key(api_key) when is_binary(api_key) do
    # First check if it's an api_keys table key
    case Repo.get_by(ApiKey, key: api_key, active: true) do
      %ApiKey{customer_id: customer_id} ->
        get_customer!(customer_id)
      nil ->
        # Check customers table
        case Repo.get_by(Customer, api_key: api_key, active: true) do
          nil ->
            # Fall back to LegacyAccounts for test and demo keys
            Rsolv.LegacyAccounts.get_customer_by_api_key(api_key)
          customer ->
            customer
        end
    end
  end

  @doc """
  Creates a customer for a user.

  ## Examples

      iex> create_customer(user, %{field: value})
      {:ok, %Customer{}}

      iex> create_customer(user, %{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def create_customer(user, attrs \\ %{}) do
    attrs = Map.put(attrs, :user_id, user.id)
    
    %Customer{}
    |> Customer.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a customer.

  ## Examples

      iex> update_customer(customer, %{field: new_value})
      {:ok, %Customer{}}

      iex> update_customer(customer, %{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def update_customer(%Customer{} = customer, attrs) do
    customer
    |> Customer.changeset(attrs)
    |> Repo.update()
  end
  
  # Handle legacy customers (plain maps) during transition
  def update_customer(customer, attrs) when is_map(customer) and not is_struct(customer) do
    Rsolv.LegacyAccounts.update_customer(customer, attrs)
  end

  @doc """
  Deletes a customer.

  ## Examples

      iex> delete_customer(customer)
      {:ok, %Customer{}}

      iex> delete_customer(customer)
      {:error, %Ecto.Changeset{}}

  """
  def delete_customer(%Customer{} = customer) do
    Repo.delete(customer)
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking customer changes.

  ## Examples

      iex> change_customer(customer)
      %Ecto.Changeset{data: %Customer{}}

  """
  def change_customer(%Customer{} = customer, attrs \\ %{}) do
    Customer.changeset(customer, attrs)
  end

  @doc """
  Creates an API key for a customer.

  ## Examples

      iex> create_api_key(customer, %{name: "Production Key"})
      {:ok, %ApiKey{}}

      iex> create_api_key(customer, %{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def create_api_key(%Customer{} = customer, attrs \\ %{}) do
    attrs = Map.put(attrs, :customer_id, customer.id)
    
    %ApiKey{}
    |> ApiKey.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Lists API keys for a customer.

  ## Examples

      iex> list_api_keys(customer)
      [%ApiKey{}, ...]

  """
  def list_api_keys(%Customer{id: customer_id}) do
    ApiKey
    |> where([k], k.customer_id == ^customer_id)
    |> order_by([k], desc: k.inserted_at)
    |> Repo.all()
  end

  @doc """
  Increments usage for a customer.

  ## Examples

      iex> increment_usage(customer, 1)
      {:ok, %Customer{}}

  """
  def increment_usage(%Customer{} = customer, amount) when is_integer(amount) do
    from(c in Customer,
      where: c.id == ^customer.id,
      update: [inc: [current_usage: ^amount]]
    )
    |> Repo.update_all([])
    
    {:ok, Repo.get!(Customer, customer.id)}
  end

  @doc """
  Resets usage for all customers (typically run monthly).
  """
  def reset_all_usage do
    from(c in Customer, update: [set: [current_usage: 0]])
    |> Repo.update_all([])
  end
end