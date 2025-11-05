defmodule Rsolv.FunnelTracking.CustomerJourney do
  @moduledoc """
  Schema for tracking an individual customer's journey through the conversion funnel.

  Each customer has exactly one journey record that tracks their progress through:
  1. First website visit
  2. Signup
  3. API key creation
  4. First API call (activation)
  5. Second+ API call (retention)
  """

  use Ecto.Schema
  import Ecto.Changeset

  schema "customer_journeys" do
    belongs_to :customer, Rsolv.Customers.Customer

    field :visitor_id, :string
    field :session_id, :string

    # Timestamps for each funnel stage
    field :first_visit_at, :utc_datetime
    field :signup_at, :utc_datetime
    field :api_key_created_at, :utc_datetime
    field :first_api_call_at, :utc_datetime
    field :second_api_call_at, :utc_datetime

    # Conversion timings (in seconds)
    field :visit_to_signup_seconds, :integer
    field :signup_to_api_key_seconds, :integer
    field :api_key_to_first_call_seconds, :integer
    field :first_to_second_call_seconds, :integer

    # UTM attribution (from first touch)
    field :utm_source, :string
    field :utm_medium, :string
    field :utm_campaign, :string
    field :utm_term, :string
    field :utm_content, :string

    # Flags for funnel completion
    field :completed_signup, :boolean, default: false
    field :completed_api_key, :boolean, default: false
    field :completed_activation, :boolean, default: false
    field :completed_retention, :boolean, default: false

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(journey, attrs) do
    journey
    |> cast(attrs, [
      :customer_id,
      :visitor_id,
      :session_id,
      :first_visit_at,
      :signup_at,
      :api_key_created_at,
      :first_api_call_at,
      :second_api_call_at,
      :visit_to_signup_seconds,
      :signup_to_api_key_seconds,
      :api_key_to_first_call_seconds,
      :first_to_second_call_seconds,
      :utm_source,
      :utm_medium,
      :utm_campaign,
      :utm_term,
      :utm_content,
      :completed_signup,
      :completed_api_key,
      :completed_activation,
      :completed_retention
    ])
    |> validate_required([:customer_id])
    |> unique_constraint(:customer_id)
    |> validate_number(:visit_to_signup_seconds, greater_than_or_equal_to: 0)
    |> validate_number(:signup_to_api_key_seconds, greater_than_or_equal_to: 0)
    |> validate_number(:api_key_to_first_call_seconds, greater_than_or_equal_to: 0)
    |> validate_number(:first_to_second_call_seconds, greater_than_or_equal_to: 0)
  end

  @doc """
  Update journey with signup information.
  """
  def record_signup(journey, signup_at, utm_params \\ %{}) do
    now = signup_at || DateTime.utc_now()

    changes = %{
      signup_at: now,
      completed_signup: true
    }

    # Calculate time from first visit if available
    changes =
      if journey.first_visit_at do
        Map.put(changes, :visit_to_signup_seconds, DateTime.diff(now, journey.first_visit_at))
      else
        changes
      end

    # Merge UTM params if provided
    changes = Map.merge(changes, utm_params)

    changeset(journey, changes)
  end

  @doc """
  Update journey with API key creation.
  """
  def record_api_key_creation(journey, created_at) do
    now = created_at || DateTime.utc_now()

    changes = %{
      api_key_created_at: now,
      completed_api_key: true
    }

    # Calculate time from signup
    changes =
      if journey.signup_at do
        Map.put(changes, :signup_to_api_key_seconds, DateTime.diff(now, journey.signup_at))
      else
        changes
      end

    changeset(journey, changes)
  end

  @doc """
  Update journey with first API call (activation).
  """
  def record_first_api_call(journey, called_at) do
    now = called_at || DateTime.utc_now()

    changes = %{
      first_api_call_at: now,
      completed_activation: true
    }

    # Calculate time from API key creation
    changes =
      if journey.api_key_created_at do
        Map.put(
          changes,
          :api_key_to_first_call_seconds,
          DateTime.diff(now, journey.api_key_created_at)
        )
      else
        changes
      end

    changeset(journey, changes)
  end

  @doc """
  Update journey with second API call (retention).
  """
  def record_second_api_call(journey, called_at) do
    now = called_at || DateTime.utc_now()

    changes = %{
      second_api_call_at: now,
      completed_retention: true
    }

    # Calculate time from first API call
    changes =
      if journey.first_api_call_at do
        Map.put(
          changes,
          :first_to_second_call_seconds,
          DateTime.diff(now, journey.first_api_call_at)
        )
      else
        changes
      end

    changeset(journey, changes)
  end
end
