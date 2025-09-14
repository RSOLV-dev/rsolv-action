defmodule Rsolv.Customers do
  @moduledoc """
  The Customers context.
  """

  import Ecto.Query, warn: false
  alias Rsolv.Repo
  require Logger

  alias Rsolv.Customers.{Customer, ApiKey}
  
  @doc """
  Gets an API key by its key value.
  
  ## Examples
  
      iex> get_api_key_by_key("test_abc123")
      %ApiKey{}
      
      iex> get_api_key_by_key("invalid")
      nil
  """
  def get_api_key_by_key(key) when is_binary(key) do
    Repo.get_by(ApiKey, key: key, active: true)
    |> Repo.preload(:customer)
  end
  def get_api_key_by_key(_), do: nil

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
  def get_customer_by_api_key(nil), do: nil
  def get_customer_by_api_key(api_key) when is_binary(api_key) do
    # First check if it's an api_keys table key
    case Repo.get_by(ApiKey, key: api_key, active: true) do
      %ApiKey{customer_id: customer_id} ->
        customer = get_customer!(customer_id)
        # Only return customer if they are active
        if customer.active do
          customer
        else
          nil
        end
      nil ->
        # No customer found with this API key
        nil
    end
  end

  @doc """
  Creates a customer.
  
  DEPRECATED: This function requiring a user is deprecated.
  Use register_customer/1 for new customers with passwords.

  ## Examples

      iex> create_customer(%{name: "Test", email: "test@example.com"})
      {:ok, %Customer{}}

      iex> create_customer(%{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def create_customer(attrs) when is_map(attrs) do
    changeset = if Map.has_key?(attrs, :password) or Map.has_key?(attrs, "password") do
      # Use registration changeset when password is provided
      Customer.registration_changeset(%Customer{}, attrs)
    else
      # Use regular changeset for customers without passwords (e.g., API-only customers)
      Customer.changeset(%Customer{}, attrs)
    end
    
    Repo.insert(changeset)
  end
  
  # Legacy support for user-based creation (deprecated)
  def create_customer(user, attrs) when is_struct(user) do
    create_customer(attrs)
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
  
  # Legacy support removed - all customers must be structs
  def update_customer(customer, _attrs) when is_map(customer) and not is_struct(customer) do
    {:error, "Legacy customer format no longer supported"}
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
  
  ## Authentication Functions
  
  @doc """
  Registers a new customer with email and password.
  
  ## Examples
  
      iex> register_customer(%{email: "test@example.com", password: "SecureP@ss123!", name: "Test"})
      {:ok, %Customer{}}
      
      iex> register_customer(%{email: "bad", password: "weak"})
      {:error, %Ecto.Changeset{}}
  """
  def register_customer(attrs) do
    %Customer{}
    |> Customer.registration_changeset(attrs)
    |> Repo.insert()
  end
  
  @doc """
  Gets a customer by email.
  """
  def get_customer_by_email(email) when is_binary(email) do
    Repo.get_by(Customer, email: email)
  end
  
  @doc """
  Authenticates a customer by email and password.
  
  Uses the Mnesia-based rate limiter to prevent brute force attacks.
  
  ## Examples
  
      iex> authenticate_customer_by_email_and_password("test@example.com", "correct_password")
      {:ok, %Customer{}}
      
      iex> authenticate_customer_by_email_and_password("test@example.com", "wrong_password")
      {:error, :invalid_credentials}
      
      iex> # After too many attempts
      iex> authenticate_customer_by_email_and_password("test@example.com", "any_password")
      {:error, :too_many_attempts}
  """
  def authenticate_customer_by_email_and_password(email, password)
      when is_binary(email) and is_binary(password) do
    # Use email hash as a pseudo customer_id for rate limiting
    # This prevents email enumeration while still rate limiting per email
    pseudo_id = :crypto.hash(:sha256, email) |> Base.encode16()
    
    case Rsolv.RateLimiter.check_rate_limit(pseudo_id, :auth_attempt) do
      :ok ->
        # Proceed with authentication
        customer = get_customer_by_email(email)
        
        if Customer.valid_password?(customer, password) do
          # Successful authentication - no way to reset individual keys in current RateLimiter
          {:ok, customer}
        else
          # Failed authentication
          {:error, :invalid_credentials}
        end
        
      {:error, :rate_limited} ->
        {:error, :too_many_attempts}
    end
  end
  
  def authenticate_customer_by_email_and_password(_, _) do
    # Prevent timing attacks even with nil inputs
    Bcrypt.no_user_verify()
    {:error, :invalid_credentials}
  end
  
  ## Session token management
  
  @doc """
  Generates a session token for a customer.
  """
  def generate_customer_session_token(customer) do
    token = :crypto.strong_rand_bytes(32) |> Base.url_encode64()
    
    # Store in distributed Mnesia table for cluster-wide access
    case Rsolv.CustomerSessions.put_session(token, customer.id) do
      {:atomic, _result} -> 
        token
      error ->
        Logger.error("Failed to store session: #{inspect(error)}")
        raise "Failed to create session token"
    end
  end
  
  @doc """
  Gets a customer by session token.
  """
  def get_customer_by_session_token(token) do
    case Rsolv.CustomerSessions.get_session(token) do
      {:ok, customer_id} ->
        get_customer!(customer_id)
      {:error, :not_found} ->
        nil
      {:error, :expired} ->
        nil
      {:error, reason} ->
        Logger.error("Failed to retrieve session: #{inspect(reason)}")
        nil
    end
  rescue
    _ -> nil
  end
  
  @doc """
  Deletes a session token.
  """
  def delete_session_token(token) do
    Rsolv.CustomerSessions.delete_session(token)
    :ok
  end
end