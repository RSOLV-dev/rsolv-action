defmodule Rsolv.Analytics.Event do
  @moduledoc """
  Schema for tracking custom events (button clicks, form submissions, etc.).
  """
  
  use Ecto.Schema
  import Ecto.Changeset
  
  schema "analytics_events" do
    field :event_name, :string
    field :properties, :map, default: %{}
    field :session_id, :string
    
    belongs_to :user, Rsolv.Accounts.User
    
    timestamps(type: :utc_datetime)
  end
  
  def changeset(event, attrs) do
    event
    |> cast(attrs, [:event_name, :properties, :user_id, :session_id])
    |> validate_required([:event_name])
    |> validate_length(:event_name, max: 255)
    |> validate_length(:session_id, max: 255)
  end
end