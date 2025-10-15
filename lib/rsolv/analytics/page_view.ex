defmodule Rsolv.Analytics.PageView do
  @moduledoc """
  Schema for tracking page views with UTM parameters and user context.
  """

  use Ecto.Schema
  import Ecto.Changeset

  schema "analytics_page_views" do
    field :path, :string
    field :user_ip, :string
    field :utm_source, :string
    field :utm_medium, :string
    field :utm_campaign, :string
    field :utm_term, :string
    field :utm_content, :string
    field :session_id, :string
    field :user_agent, :string
    field :referrer, :string

    belongs_to :customer, Rsolv.Customers.Customer

    timestamps(type: :utc_datetime)
  end

  def changeset(page_view, attrs) do
    page_view
    |> cast(attrs, [
      :path,
      :user_ip,
      :utm_source,
      :utm_medium,
      :utm_campaign,
      :utm_term,
      :utm_content,
      :customer_id,
      :session_id,
      :user_agent,
      :referrer
    ])
    |> validate_required([:path])
    |> validate_length(:path, max: 2048)
    |> validate_length(:utm_source, max: 255)
    |> validate_length(:utm_medium, max: 255)
    |> validate_length(:utm_campaign, max: 255)
    |> validate_length(:utm_term, max: 255)
    |> validate_length(:utm_content, max: 255)
    |> validate_length(:session_id, max: 255)
    |> validate_length(:user_agent, max: 1024)
    |> validate_length(:referrer, max: 2048)
  end
end
