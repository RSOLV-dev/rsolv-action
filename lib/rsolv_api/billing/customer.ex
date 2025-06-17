defmodule RsolvApi.Billing.Customer do
  @moduledoc """
  Customer schema for billing and subscription management.
  """
  
  use Ecto.Schema
  import Ecto.Changeset

  schema "customers" do
    field :name, :string
    field :email, :string
    field :api_key, :string
    field :active, :boolean, default: true
    field :trial_fixes_used, :integer, default: 0
    field :trial_fixes_limit, :integer, default: 10
    field :trial_expired, :boolean, default: false
    field :subscription_plan, :string, default: "pay_as_you_go"
    field :rollover_fixes, :integer, default: 0
    field :stripe_customer_id, :string
    field :metadata, :map, default: %{}

    timestamps()
  end

  @required_fields ~w(name email api_key)a
  @optional_fields ~w(active trial_fixes_used trial_fixes_limit trial_expired
                     subscription_plan rollover_fixes stripe_customer_id metadata)a

  def changeset(customer, attrs) do
    customer
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_format(:email, ~r/@/)
    |> unique_constraint(:api_key)
    |> unique_constraint(:email)
  end
end