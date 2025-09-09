defmodule Rsolv.Customers.Customer do
  use Ecto.Schema
  import Ecto.Changeset

  schema "customers" do
    field :name, :string
    field :email, :string
    field :monthly_limit, :integer, default: 100
    field :current_usage, :integer, default: 0
    field :active, :boolean, default: true
    field :metadata, :map, default: %{}
    
    # Billing fields from Billing.Customer
    field :trial_fixes_used, :integer, default: 0
    field :trial_fixes_limit, :integer, default: 5
    field :stripe_customer_id, :string
    field :subscription_plan, :string, default: "trial"
    field :subscription_status, :string, default: "active"
    field :rollover_fixes, :integer, default: 0
    field :payment_method_added_at, :utc_datetime
    field :trial_expired_at, :utc_datetime
    field :fixes_used_this_month, :integer, default: 0
    field :fixes_quota_this_month, :integer, default: 0
    field :has_payment_method, :boolean, default: false
    
    belongs_to :user, Rsolv.Accounts.User
    has_many :api_keys, Rsolv.Customers.ApiKey
    has_many :fix_attempts, Rsolv.Billing.FixAttempt
    has_many :forge_accounts, Rsolv.Customers.ForgeAccount
    
    timestamps()
  end

  @doc false
  def changeset(customer, attrs) do
    customer
    |> cast(attrs, [
      :name, :email, :monthly_limit, :current_usage, :active, :metadata, :user_id,
      :trial_fixes_used, :trial_fixes_limit, :stripe_customer_id, :subscription_plan,
      :subscription_status, :rollover_fixes, :payment_method_added_at, :trial_expired_at,
      :fixes_used_this_month, :fixes_quota_this_month, :has_payment_method
    ])
    |> validate_required([:name, :email, :user_id])
    |> validate_format(:email, ~r/^[^\s]+@[^\s]+$/, message: "must have the @ sign and no spaces")
    |> unique_constraint(:email)
  end
  
  @doc """
  Checks if the customer's trial has expired.
  
  Returns true if trial_expired_at is set and in the past.
  """
  def trial_expired?(%__MODULE__{trial_expired_at: nil}), do: false
  def trial_expired?(%__MODULE__{trial_expired_at: expired_at}) do
    DateTime.compare(expired_at, DateTime.utc_now()) == :lt
  end
end

# Implement the FunWithFlags.Actor protocol for Customer
defimpl FunWithFlags.Actor, for: Rsolv.Customers.Customer do
  def id(%{id: id}), do: "customer:#{id}"
end