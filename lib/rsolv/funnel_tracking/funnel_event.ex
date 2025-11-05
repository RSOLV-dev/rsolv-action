defmodule Rsolv.FunnelTracking.FunnelEvent do
  @moduledoc """
  Schema for tracking individual funnel events.

  Event types:
  - "page_view" - Website page view
  - "signup" - User signed up for early access or created account
  - "api_key_created" - User created an API key
  - "first_api_call" - User made their first API call (activation)
  - "api_call" - Subsequent API calls (for retention tracking)
  """

  use Ecto.Schema
  import Ecto.Changeset

  @event_types ~w(page_view signup api_key_created first_api_call api_call)

  schema "funnel_events" do
    belongs_to :customer, Rsolv.Customers.Customer

    field :event_type, :string
    field :session_id, :string
    field :visitor_id, :string
    field :ip_address, :string
    field :user_agent, :string
    field :referrer, :string
    field :utm_source, :string
    field :utm_medium, :string
    field :utm_campaign, :string
    field :utm_term, :string
    field :utm_content, :string
    field :metadata, :map, default: %{}

    timestamps(type: :utc_datetime, updated_at: false)
  end

  @doc false
  def changeset(event, attrs) do
    event
    |> cast(attrs, [
      :customer_id,
      :event_type,
      :session_id,
      :visitor_id,
      :ip_address,
      :user_agent,
      :referrer,
      :utm_source,
      :utm_medium,
      :utm_campaign,
      :utm_term,
      :utm_content,
      :metadata,
      :inserted_at
    ])
    |> validate_required([:event_type])
    |> validate_inclusion(:event_type, @event_types)
    |> validate_length(:event_type, max: 50)
    |> validate_length(:visitor_id, max: 255)
    |> validate_length(:session_id, max: 255)
    |> validate_length(:utm_source, max: 100)
    |> validate_length(:utm_medium, max: 100)
    |> validate_length(:utm_campaign, max: 100)
    |> validate_length(:utm_term, max: 100)
    |> validate_length(:utm_content, max: 100)
  end
end
