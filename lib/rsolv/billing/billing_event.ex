defmodule Rsolv.Billing.BillingEvent do
  @moduledoc """
  Billing event from Stripe webhooks.

  Provides idempotency and audit trail for all Stripe events.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "billing_events" do
    field :stripe_event_id, :string
    field :event_type, :string
    field :amount_cents, :integer
    field :metadata, :map, default: %{}

    belongs_to :customer, Rsolv.Customers.Customer, type: :integer

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(event, attrs) do
    event
    |> cast(attrs, [:customer_id, :stripe_event_id, :event_type, :amount_cents, :metadata])
    |> validate_required([:stripe_event_id, :event_type])
    |> unique_constraint(:stripe_event_id)
    |> foreign_key_constraint(:customer_id)
  end
end
