defmodule RsolvWeb.Helpers.RateLimitHelper do
  @moduledoc """
  Helper functions for rate limiting with consistent error handling.

  Provides reusable rate limiting logic for both controllers and LiveViews.
  """

  alias Rsolv.RateLimiter

  @doc """
  Checks rate limit and returns a standardized result.

  Returns `{:ok, metadata}` if request is allowed, or `{:error, :rate_limited, message, metadata}`
  if the rate limit has been exceeded.

  ## Examples

      iex> {:ok, metadata} = RsolvWeb.Helpers.RateLimitHelper.check_and_format("test-127.0.0.1", :customer_onboarding)
      iex> Map.keys(metadata) |> Enum.sort()
      [:limit, :remaining, :reset]

  """
  @spec check_and_format(String.t(), atom()) ::
          {:ok, map()} | {:error, :rate_limited, String.t(), map()}
  def check_and_format(identifier, action) do
    case RateLimiter.check_rate_limit(identifier, action) do
      {:ok, metadata} ->
        {:ok, metadata}

      {:error, :rate_limited, metadata} ->
        message = format_rate_limit_message(action, metadata)
        {:error, :rate_limited, message, metadata}
    end
  end

  @doc """
  Formats a user-friendly rate limit error message with time remaining.

  ## Examples

      iex> metadata = %{reset: System.system_time(:second) + 120}
      iex> message = RsolvWeb.Helpers.RateLimitHelper.format_rate_limit_message(:customer_onboarding, metadata)
      iex> message =~ "Too many signup attempts"
      true

  """
  @spec format_rate_limit_message(atom(), map()) :: String.t()
  def format_rate_limit_message(action, %{reset: reset_time}) do
    seconds_remaining = reset_time - System.system_time(:second)
    minutes_remaining = div(seconds_remaining, 60)

    time_text =
      cond do
        minutes_remaining > 1 -> "#{minutes_remaining} minutes"
        minutes_remaining == 1 -> "1 minute"
        true -> "#{seconds_remaining} seconds"
      end

    action_text = action_description(action)
    "Too many #{action_text} attempts. Please try again in #{time_text}."
  end

  defp action_description(:customer_onboarding), do: "signup"
  defp action_description(:credential_exchange), do: "credential exchange"
  defp action_description(:auth_attempt), do: "login"
  defp action_description(_), do: "request"
end
