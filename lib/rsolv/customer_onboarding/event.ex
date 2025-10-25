defmodule Rsolv.CustomerOnboarding.Event do
  @moduledoc """
  Schema for customer onboarding events audit trail.

  Tracks key events during the customer provisioning and onboarding process
  for debugging, analytics, and audit purposes.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}

  schema "customer_onboarding_events" do
    belongs_to :customer, Rsolv.Customers.Customer, type: :id

    field :event_type, :string
    field :status, :string
    field :metadata, :map, default: %{}

    timestamps(type: :utc_datetime_usec)
  end

  @event_types ~w(customer_created api_key_generated email_sent)
  @statuses ~w(success failed retrying)

  def valid_statuses, do: @statuses
  def valid_event_types, do: @event_types

  @doc false
  def changeset(event, attrs) do
    event
    |> cast(attrs, [:customer_id, :event_type, :status, :metadata])
    |> validate_required([:customer_id, :event_type, :status])
    |> validate_inclusion(:event_type, @event_types)
    |> validate_inclusion(:status, @statuses)
    |> foreign_key_constraint(:customer_id)
  end
end
