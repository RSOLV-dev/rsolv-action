defmodule Rsolv.Analytics.Event do
  use Ecto.Schema
  import Ecto.Changeset

  schema "analytics_events" do
    field :event_type, :string
    field :visitor_id, :string
    field :session_id, :string
    field :page_path, :string
    field :referrer, :string
    field :user_agent, :string
    field :ip_address, :string
    field :utm_source, :string
    field :utm_medium, :string
    field :utm_campaign, :string
    field :utm_term, :string
    field :utm_content, :string
    field :metadata, :map, default: %{}

    timestamps()
  end

  @doc false
  def changeset(event, attrs) do
    event
    |> cast(attrs, [
      :event_type,
      :visitor_id,
      :session_id,
      :page_path,
      :referrer,
      :user_agent,
      :ip_address,
      :utm_source,
      :utm_medium,
      :utm_campaign,
      :utm_term,
      :utm_content,
      :metadata,
      :inserted_at,
      :updated_at
    ])
    |> validate_required([:event_type])
    |> validate_length(:event_type, max: 50)
    |> validate_length(:visitor_id, max: 255)
    |> validate_length(:session_id, max: 255)
    |> validate_length(:page_path, max: 500)
    |> validate_length(:referrer, max: 500)
    |> validate_length(:utm_source, max: 100)
    |> validate_length(:utm_medium, max: 100)
    |> validate_length(:utm_campaign, max: 100)
    |> validate_length(:utm_term, max: 100)
    |> validate_length(:utm_content, max: 100)
  end
end
