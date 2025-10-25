defmodule Rsolv.Billing.Subscription do
  @moduledoc """
  Pro subscription record.

  Tracks Stripe subscription lifecycle and billing periods.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "subscriptions" do
    field :stripe_subscription_id, :string
    field :plan, :string
    field :status, :string
    field :current_period_start, :utc_datetime
    field :current_period_end, :utc_datetime
    field :cancel_at_period_end, :boolean, default: false

    belongs_to :customer, Rsolv.Customers.Customer, type: :integer

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(subscription, attrs) do
    subscription
    |> cast(attrs, [
      :customer_id,
      :stripe_subscription_id,
      :plan,
      :status,
      :current_period_start,
      :current_period_end,
      :cancel_at_period_end
    ])
    |> validate_required([:customer_id, :stripe_subscription_id, :plan, :status])
    |> validate_inclusion(:plan, ["pro"])
    |> validate_inclusion(:status, ["active", "past_due", "canceled", "unpaid"])
    |> unique_constraint(:stripe_subscription_id)
    |> foreign_key_constraint(:customer_id)
  end
end
