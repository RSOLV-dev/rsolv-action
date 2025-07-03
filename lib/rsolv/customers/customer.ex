defmodule Rsolv.Customers.Customer do
  use Ecto.Schema
  import Ecto.Changeset

  schema "customers" do
    field :name, :string
    field :email, :string
    field :api_key, :string
    field :monthly_limit, :integer, default: 100
    field :current_usage, :integer, default: 0
    field :active, :boolean, default: true
    field :metadata, :map, default: %{}
    field :github_org, :string
    field :plan, :string, default: "trial"
    
    belongs_to :user, Rsolv.Accounts.User
    has_many :api_keys, Rsolv.Customers.ApiKey
    has_many :fix_attempts, Rsolv.Billing.FixAttempt
    
    timestamps()
  end

  @doc false
  def changeset(customer, attrs) do
    customer
    |> cast(attrs, [:name, :email, :api_key, :monthly_limit, :current_usage, :active, :metadata, :user_id, :github_org, :plan])
    |> validate_required([:name, :email, :user_id])
    |> validate_format(:email, ~r/^[^\s]+@[^\s]+$/, message: "must have the @ sign and no spaces")
    |> generate_api_key_if_missing()
    |> unique_constraint(:email)
    |> unique_constraint(:api_key)
  end
  
  defp generate_api_key_if_missing(changeset) do
    case get_change(changeset, :api_key) do
      nil ->
        put_change(changeset, :api_key, generate_api_key())
      _ ->
        changeset
    end
  end
  
  defp generate_api_key do
    "rsolv_#{Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)}"
  end
end