defmodule Rsolv.Helpers.Funnel do
  @moduledoc """
  IEx helper functions for querying and analyzing funnel metrics.

  These functions provide a convenient interface for exploring conversion
  funnel data in the IEx console.

  ## Usage

  In IEx:
      iex> import Rsolv.Helpers.Funnel

      # Get summary for last 30 days
      iex> summary()

      # Get summary for last 7 days
      iex> summary(7)

      # Show drop-off points
      iex> drop_offs()

      # List recent signups
      iex> recent_signups(10)

      # Find customers who haven't activated
      iex> not_activated()
  """

  alias Rsolv.FunnelTracking
  alias Rsolv.FunnelTracking.CustomerJourney
  alias Rsolv.Repo
  require Logger

  @doc """
  Get funnel summary for the last N days (default: 30).

  Returns conversion rates and counts at each funnel stage.
  """
  def summary(days \\ 30) do
    metrics = FunnelTracking.get_funnel_summary(days)

    IO.puts(
      "\n" <>
        IO.ANSI.cyan() <>
        "=== Conversion Funnel Summary (Last #{days} Days) ===" <> IO.ANSI.reset()
    )

    IO.puts("")

    IO.puts("📊 Stage Counts:")

    IO.puts(
      "  └─ Website Visits:     #{format_number(metrics.website_visits)} (#{metrics.unique_visitors} unique)"
    )

    IO.puts(
      "     └─ Signups:         #{format_number(metrics.signups)} (#{format_rate(metrics.visit_to_signup_rate)})"
    )

    IO.puts(
      "        └─ API Keys:     #{format_number(metrics.api_keys_created)} (#{format_rate(metrics.signup_to_api_key_rate)})"
    )

    IO.puts(
      "           └─ Activated: #{format_number(metrics.activated_users)} (#{format_rate(metrics.api_key_to_activation_rate)})"
    )

    IO.puts(
      "              └─ Retained: #{format_number(metrics.retained_users)} (#{format_rate(metrics.activation_to_retention_rate)})"
    )

    IO.puts("")

    IO.puts("🎯 Overall Conversion:")

    overall_rate =
      if metrics.website_visits > 0 do
        Decimal.from_float(metrics.retained_users / metrics.website_visits * 100)
        |> Decimal.round(2)
      else
        Decimal.new("0.00")
      end

    IO.puts("  Visit → Retained User: #{format_rate(overall_rate)}")
    IO.puts("")

    if map_size(metrics.top_utm_sources) > 0 do
      IO.puts("📈 Top UTM Sources:")

      metrics.top_utm_sources
      |> Enum.sort_by(fn {_k, v} -> v end, :desc)
      |> Enum.take(5)
      |> Enum.each(fn {source, count} ->
        IO.puts("  - #{source}: #{count}")
      end)

      IO.puts("")
    end

    metrics
  end

  @doc """
  Show drop-off analysis - identify biggest conversion problems.
  """
  def drop_offs(days \\ 30) do
    metrics = FunnelTracking.get_funnel_summary(days)

    drop_offs = [
      {"Visit → Signup", metrics.website_visits - metrics.signups, metrics.visit_to_signup_rate},
      {"Signup → API Key", metrics.signups - metrics.api_keys_created,
       metrics.signup_to_api_key_rate},
      {"API Key → Activation", metrics.api_keys_created - metrics.activated_users,
       metrics.api_key_to_activation_rate},
      {"Activation → Retention", metrics.activated_users - metrics.retained_users,
       metrics.activation_to_retention_rate}
    ]

    IO.puts(
      "\n" <> IO.ANSI.red() <> "=== Drop-Off Analysis (Last #{days} Days) ===" <> IO.ANSI.reset()
    )

    IO.puts("")

    drop_offs
    |> Enum.sort_by(fn {_stage, count, _rate} -> count end, :desc)
    |> Enum.with_index(1)
    |> Enum.each(fn {{stage, lost, conversion_rate}, index} ->
      severity =
        cond do
          Decimal.to_float(conversion_rate) < 10.0 -> "🔴 CRITICAL"
          Decimal.to_float(conversion_rate) < 30.0 -> "🟠 HIGH"
          Decimal.to_float(conversion_rate) < 50.0 -> "🟡 MEDIUM"
          true -> "🟢 OK"
        end

      IO.puts("#{index}. #{stage}")

      IO.puts(
        "   Lost: #{lost} users (#{format_rate(Decimal.new(100) |> Decimal.sub(conversion_rate))} drop-off)"
      )

      IO.puts("   Status: #{severity}")
      IO.puts("")
    end)

    :ok
  end

  @doc """
  List recent customer journeys.
  """
  def recent_journeys(limit \\ 10) do
    journeys =
      CustomerJourney
      |> Repo.all()
      |> Enum.sort_by(& &1.inserted_at, {:desc, DateTime})
      |> Enum.take(limit)
      |> Repo.preload(:customer)

    IO.puts("\n" <> IO.ANSI.cyan() <> "=== Recent Customer Journeys ===" <> IO.ANSI.reset())
    IO.puts("")

    journeys
    |> Enum.each(fn journey ->
      customer = journey.customer
      IO.puts("Customer: #{customer.name} (#{customer.email})")
      IO.puts("  ✅ Signed up: #{format_datetime(journey.signup_at)}")

      IO.puts(
        "  #{if journey.completed_api_key, do: "✅", else: "⏳"} API Key: #{format_datetime(journey.api_key_created_at)}"
      )

      IO.puts(
        "  #{if journey.completed_activation, do: "✅", else: "⏳"} Activated: #{format_datetime(journey.first_api_call_at)}"
      )

      IO.puts(
        "  #{if journey.completed_retention, do: "✅", else: "⏳"} Retained: #{format_datetime(journey.second_api_call_at)}"
      )

      if journey.utm_source do
        IO.puts(
          "  📍 Source: #{journey.utm_source}" <>
            if(journey.utm_campaign, do: " / #{journey.utm_campaign}", else: "")
        )
      end

      IO.puts("")
    end)

    journeys
  end

  @doc """
  Find customers who signed up but haven't created API keys.
  """
  def not_created_api_key(limit \\ 10) do
    journeys =
      FunnelTracking.list_journeys(limit: limit)
      |> Enum.filter(fn j -> j.completed_signup && !j.completed_api_key end)
      |> Repo.preload(:customer)

    IO.puts("\n" <> IO.ANSI.yellow() <> "=== Customers Without API Keys ===" <> IO.ANSI.reset())
    IO.puts("")

    if Enum.empty?(journeys) do
      IO.puts("✅ All customers have created API keys!")
    else
      journeys
      |> Enum.each(fn journey ->
        days_ago =
          if journey.signup_at do
            DateTime.diff(DateTime.utc_now(), journey.signup_at, :day)
          else
            "?"
          end

        IO.puts("- #{journey.customer.email} (#{days_ago} days ago)")
      end)
    end

    IO.puts("")
    journeys
  end

  @doc """
  Find customers who created API keys but haven't made their first call.
  """
  def not_activated(limit \\ 10) do
    journeys =
      FunnelTracking.list_journeys(
        completed_activation: false,
        # Get more to filter
        limit: limit * 2
      )
      |> Enum.filter(fn j -> j.completed_api_key && !j.completed_activation end)
      |> Enum.take(limit)
      |> Repo.preload(:customer)

    IO.puts("\n" <> IO.ANSI.yellow() <> "=== Customers Not Yet Activated ===" <> IO.ANSI.reset())
    IO.puts("")

    if Enum.empty?(journeys) do
      IO.puts("✅ All customers with API keys have activated!")
    else
      journeys
      |> Enum.each(fn journey ->
        days_ago =
          if journey.api_key_created_at do
            DateTime.diff(DateTime.utc_now(), journey.api_key_created_at, :day)
          else
            "?"
          end

        IO.puts("- #{journey.customer.email} (API key created #{days_ago} days ago)")
      end)
    end

    IO.puts("")
    journeys
  end

  @doc """
  Find customers who activated but haven't retained (2nd call).
  """
  def not_retained(limit \\ 10) do
    journeys =
      FunnelTracking.list_journeys(
        completed_activation: true,
        completed_retention: false,
        limit: limit
      )
      |> Repo.preload(:customer)

    IO.puts("\n" <> IO.ANSI.yellow() <> "=== Customers Not Yet Retained ===" <> IO.ANSI.reset())
    IO.puts("")

    if Enum.empty?(journeys) do
      IO.puts("✅ All activated customers have retained!")
    else
      journeys
      |> Enum.each(fn journey ->
        days_ago =
          if journey.first_api_call_at do
            DateTime.diff(DateTime.utc_now(), journey.first_api_call_at, :day)
          else
            "?"
          end

        IO.puts("- #{journey.customer.email} (first call #{days_ago} days ago)")
      end)
    end

    IO.puts("")
    journeys
  end

  @doc """
  Show daily breakdown for a date range.
  """
  def daily(start_date, end_date \\ Date.utc_today()) do
    metrics_list = FunnelTracking.get_daily_metrics(start_date, end_date)

    IO.puts("\n" <> IO.ANSI.cyan() <> "=== Daily Funnel Metrics ===" <> IO.ANSI.reset())
    IO.puts("")
    IO.puts("Date       | Visits | Signups | API Keys | Activated | Retained")
    IO.puts("-----------|--------|---------|----------|-----------|----------")

    metrics_list
    |> Enum.each(fn metrics ->
      IO.puts(
        "#{metrics.period_start} | #{pad(metrics.website_visits, 6)} | #{pad(metrics.signups, 7)} | #{pad(metrics.api_keys_created, 8)} | #{pad(metrics.activated_users, 9)} | #{pad(metrics.retained_users, 8)}"
      )
    end)

    IO.puts("")
    metrics_list
  end

  ## Helper Functions

  defp format_number(num) when is_integer(num), do: Integer.to_string(num)
  defp format_number(num), do: to_string(num)

  defp format_rate(%Decimal{} = rate) do
    "#{Decimal.to_string(rate)}%"
  end

  defp format_datetime(nil), do: "N/A"

  defp format_datetime(%DateTime{} = dt) do
    Calendar.strftime(dt, "%Y-%m-%d %H:%M")
  end

  defp pad(value, width) do
    str = to_string(value)
    String.pad_leading(str, width)
  end
end
