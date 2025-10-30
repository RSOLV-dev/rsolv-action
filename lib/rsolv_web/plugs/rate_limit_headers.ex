defmodule RsolvWeb.Plugs.RateLimitHeaders do
  @moduledoc """
  Adds rate limit headers to API responses.

  This plug checks for rate limit metadata stored in conn.assigns by the
  ApiAuthentication plug and adds the following standard headers:

  - `x-ratelimit-limit`: Maximum requests per window
  - `x-ratelimit-remaining`: Remaining requests in current window
  - `x-ratelimit-reset`: Unix timestamp when window resets

  ## Usage

  In your router pipeline:

      pipeline :api do
        plug :accepts, ["json"]
        plug RsolvWeb.Plugs.ApiAuthentication
        plug RsolvWeb.Plugs.RateLimitHeaders
      end

  The plug will automatically add headers if rate limit metadata is available.
  If no metadata is present, no headers are added (fail open).
  """

  import Plug.Conn
  require Logger

  @doc """
  Initialize the plug. No options required.
  """
  def init(opts), do: opts

  @doc """
  Register a callback to add rate limit headers before sending the response.
  This ensures headers are added after the controller action has run and
  metadata has been assigned.
  """
  def call(conn, _opts) do
    register_before_send(conn, fn conn ->
      case conn.assigns[:rate_limit_metadata] do
        %{limit: limit, remaining: remaining, reset: reset} ->
          conn
          |> put_resp_header("x-ratelimit-limit", to_string(limit))
          |> put_resp_header("x-ratelimit-remaining", to_string(remaining))
          |> put_resp_header("x-ratelimit-reset", to_string(reset))
          |> maybe_add_retry_after(remaining)

        _ ->
          # No rate limit metadata, skip adding headers
          conn
      end
    end)
  end

  # Add Retry-After header when rate limit is exceeded (remaining = 0)
  defp maybe_add_retry_after(conn, 0) do
    # Calculate seconds until reset
    case conn.assigns[:rate_limit_metadata] do
      %{reset: reset} ->
        current_time = System.system_time(:second)
        retry_after = max(0, reset - current_time)
        put_resp_header(conn, "retry-after", to_string(retry_after))

      _ ->
        conn
    end
  end

  defp maybe_add_retry_after(conn, _remaining), do: conn
end
