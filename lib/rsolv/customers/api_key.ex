defmodule Rsolv.Customers.ApiKey do
  use Ecto.Schema
  import Ecto.Changeset

  schema "api_keys" do
    field :key, :string
    field :name, :string
    field :permissions, {:array, :string}, default: []
    field :active, :boolean, default: true
    field :last_used_at, :naive_datetime
    field :expires_at, :naive_datetime
    
    belongs_to :customer, Rsolv.Customers.Customer
    
    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(api_key, attrs) do
    api_key
    |> cast(attrs, [:key, :name, :permissions, :active, :last_used_at, :expires_at, :customer_id])
    |> generate_key_if_missing()
    |> validate_required([:key, :name, :customer_id])
    |> unique_constraint(:key)
  end
  
  defp generate_key_if_missing(changeset) do
    case get_change(changeset, :key) do
      nil ->
        put_change(changeset, :key, generate_api_key())
      _ ->
        changeset
    end
  end
  
  defp generate_api_key do
    "rsolv_#{Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)}"
  end
end