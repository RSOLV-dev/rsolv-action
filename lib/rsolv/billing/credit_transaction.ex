defmodule Rsolv.Billing.CreditTransaction do
  @moduledoc """
  Credit transaction ledger entry.

  Tracks all credit additions and consumptions with full audit trail.
  Positive amounts represent credits, negative amounts represent debits.

  Source values:
  - trial_signup: Initial credits given on trial signup
  - trial_billing_added: Bonus credits when billing info is added
  - pro_subscription_payment: Credits from Pro subscription billing
  - purchased: Credits purchased via pay-as-you-go
  - consumed: Credits used for fix attempts (legacy)
  - fix_deployed: Credits consumed when a fix is deployed (RFC-066 Week 3)
  - adjustment: Manual adjustments (support, refunds, etc.)
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "credit_transactions" do
    field :amount, :integer
    field :balance_after, :integer
    field :source, :string
    field :metadata, :map, default: %{}

    belongs_to :customer, Rsolv.Customers.Customer, type: :integer

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(transaction, attrs) do
    transaction
    |> cast(attrs, [:customer_id, :amount, :balance_after, :source, :metadata])
    |> validate_required([:customer_id, :amount, :balance_after, :source])
    |> validate_inclusion(:source, [
      "trial_signup",
      "trial_billing_added",
      "pro_subscription_payment",
      "purchased",
      "consumed",
      "fix_deployed",
      "adjustment"
    ])
    |> foreign_key_constraint(:customer_id)
  end
end
