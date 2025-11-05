defmodule Rsolv.FunnelTracking.FunnelMetric do
  @moduledoc """
  Schema for pre-aggregated funnel metrics by time period.

  Stores conversion funnel statistics for efficient dashboard queries.
  Updated periodically via background jobs.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @period_types ~w(day week month)

  schema "funnel_metrics" do
    field :period_start, :date
    field :period_end, :date
    field :period_type, :string

    # Stage counts
    field :website_visits, :integer, default: 0
    field :unique_visitors, :integer, default: 0
    field :signups, :integer, default: 0
    field :api_keys_created, :integer, default: 0
    field :activated_users, :integer, default: 0
    field :retained_users, :integer, default: 0

    # Conversion rates
    field :visit_to_signup_rate, :decimal
    field :signup_to_api_key_rate, :decimal
    field :api_key_to_activation_rate, :decimal
    field :activation_to_retention_rate, :decimal

    # UTM tracking
    field :top_utm_sources, :map, default: %{}
    field :top_utm_campaigns, :map, default: %{}

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(metric, attrs) do
    metric
    |> cast(attrs, [
      :period_start,
      :period_end,
      :period_type,
      :website_visits,
      :unique_visitors,
      :signups,
      :api_keys_created,
      :activated_users,
      :retained_users,
      :visit_to_signup_rate,
      :signup_to_api_key_rate,
      :api_key_to_activation_rate,
      :activation_to_retention_rate,
      :top_utm_sources,
      :top_utm_campaigns
    ])
    |> validate_required([:period_start, :period_end, :period_type])
    |> validate_inclusion(:period_type, @period_types)
    |> validate_number(:website_visits, greater_than_or_equal_to: 0)
    |> validate_number(:unique_visitors, greater_than_or_equal_to: 0)
    |> validate_number(:signups, greater_than_or_equal_to: 0)
    |> validate_number(:api_keys_created, greater_than_or_equal_to: 0)
    |> validate_number(:activated_users, greater_than_or_equal_to: 0)
    |> validate_number(:retained_users, greater_than_or_equal_to: 0)
    |> unique_constraint([:period_start, :period_type])
    |> calculate_conversion_rates()
  end

  defp calculate_conversion_rates(changeset) do
    if changeset.valid? do
      visits = get_field(changeset, :website_visits, 0)
      signups = get_field(changeset, :signups, 0)
      api_keys = get_field(changeset, :api_keys_created, 0)
      activated = get_field(changeset, :activated_users, 0)
      retained = get_field(changeset, :retained_users, 0)

      changeset
      |> put_change(:visit_to_signup_rate, calculate_rate(signups, visits))
      |> put_change(:signup_to_api_key_rate, calculate_rate(api_keys, signups))
      |> put_change(:api_key_to_activation_rate, calculate_rate(activated, api_keys))
      |> put_change(:activation_to_retention_rate, calculate_rate(retained, activated))
    else
      changeset
    end
  end

  defp calculate_rate(_numerator, 0), do: Decimal.new("0.00")

  defp calculate_rate(numerator, denominator) do
    Decimal.from_float(numerator / denominator * 100)
    |> Decimal.round(2)
  end
end
