defmodule Rsolv.Analytics.Conversion do
  @moduledoc """
  Schema for tracking conversion events (signups, subscriptions, purchases, etc.).
  """
  
  use Ecto.Schema
  import Ecto.Changeset
  
  schema "analytics_conversions" do
    field :event_name, :string
    field :properties, :map, default: %{}
    field :session_id, :string
    field :value, :decimal  # For tracking monetary value of conversions
    
    belongs_to :customer, Rsolv.Customers.Customer
    
    timestamps(type: :utc_datetime)
  end
  
  def changeset(conversion, attrs) do
    conversion
    |> cast(attrs, [:event_name, :properties, :customer_id, :session_id, :value])
    |> validate_required([:event_name])
    |> validate_length(:event_name, max: 255)
    |> validate_length(:session_id, max: 255)
    |> validate_number(:value, greater_than_or_equal_to: 0)
  end
end