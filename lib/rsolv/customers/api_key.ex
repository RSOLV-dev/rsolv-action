defmodule Rsolv.Customers.ApiKey do
  use Ecto.Schema
  import Ecto.Changeset

  @moduledoc """
  API Key schema with SHA256 hashing for secure storage.

  API keys are generated as random strings with the format: `rsolv_<base64_encoded_random_bytes>`
  The raw key is only available at creation time and is never stored in the database.
  Instead, a SHA256 hash of the key is stored in the `key_hash` field.

  ## Security Model

  - Raw keys are generated with 32 bytes of cryptographically secure random data
  - Keys are hashed using SHA256 before storage
  - The raw key is returned only once during creation
  - Authentication compares the hash of the provided key against the stored hash
  """

  schema "api_keys" do
    field :key_hash, :string
    field :name, :string
    field :permissions, {:array, :string}, default: []
    field :active, :boolean, default: true
    field :last_used_at, :naive_datetime
    field :expires_at, :naive_datetime

    belongs_to :customer, Rsolv.Customers.Customer

    timestamps(type: :utc_datetime)
  end

  @doc """
  Creates a changeset for API key creation or update.

  When creating a new API key without a raw_key in attrs, a secure random key
  will be generated and hashed. The raw key is stored in changeset metadata
  for retrieval after insert.

  ## Parameters

  - `api_key` - The API key struct (new or existing)
  - `attrs` - Attributes map (may include :raw_key for testing)

  ## Returns

  A changeset with the key_hash field populated and raw_key in metadata
  """
  def changeset(api_key, attrs) do
    api_key
    |> cast(attrs, [:name, :permissions, :active, :last_used_at, :expires_at, :customer_id])
    |> generate_and_hash_key_if_missing(attrs)
    |> validate_required([:key_hash, :name, :customer_id])
    |> unique_constraint(:key_hash)
  end

  defp generate_and_hash_key_if_missing(changeset, attrs) do
    cond do
      # If key_hash is already set, don't generate a new one
      get_field(changeset, :key_hash) ->
        changeset

      # If raw_key is provided (for testing), use it
      Map.has_key?(attrs, :raw_key) && attrs.raw_key ->
        store_hashed_key(changeset, attrs.raw_key)

      # Generate a new random key
      true ->
        store_hashed_key(changeset, generate_api_key())
    end
  end

  # Helper to hash and store a raw key in the changeset
  defp store_hashed_key(changeset, raw_key) do
    changeset
    |> put_change(:key_hash, hash_key(raw_key))
    |> put_meta(:raw_key, raw_key)
  end

  @doc """
  Generates a secure random API key with the format: rsolv_<base64_encoded_random_bytes>
  """
  def generate_api_key do
    "rsolv_#{Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)}"
  end

  @doc """
  Hashes an API key using SHA256.

  ## Parameters

  - `raw_key` - The plaintext API key to hash

  ## Returns

  A lowercase hex-encoded SHA256 hash (64 characters)
  """
  def hash_key(raw_key) when is_binary(raw_key) do
    :crypto.hash(:sha256, raw_key) |> Base.encode16(case: :lower)
  end

  @doc """
  Verifies a raw API key against a stored hash.

  ## Parameters

  - `raw_key` - The plaintext API key to verify
  - `key_hash` - The stored hash to compare against

  ## Returns

  Boolean indicating whether the key matches the hash
  """
  def verify_key(raw_key, key_hash) when is_binary(raw_key) and is_binary(key_hash) do
    hash_key(raw_key) == key_hash
  end

  def verify_key(_, _), do: false

  # Helper to store metadata in changeset
  defp put_meta(changeset, key, value) do
    Map.update(changeset, :__meta_custom__, %{key => value}, fn meta ->
      Map.put(meta, key, value)
    end)
  end
end
