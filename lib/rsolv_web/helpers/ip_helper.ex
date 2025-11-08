defmodule RsolvWeb.Helpers.IpHelper do
  @moduledoc """
  Helper functions for extracting and formatting IP addresses from connections.

  Provides unified IP address extraction for both Phoenix controllers and LiveViews,
  handling X-Forwarded-For headers, remote_ip, and peer_data.
  """

  @doc """
  Extracts the client IP address from a Plug.Conn.

  Prioritizes X-Forwarded-For header (for proxied requests), falling back to remote_ip.

  ## Examples

      iex> conn = %Plug.Conn{remote_ip: {127, 0, 0, 1}}
      iex> RsolvWeb.Helpers.IpHelper.get_client_ip(conn)
      "127.0.0.1"

  """
  @spec get_client_ip(Plug.Conn.t()) :: String.t()
  def get_client_ip(conn) do
    case Plug.Conn.get_req_header(conn, "x-forwarded-for") do
      [ip | _] ->
        # Take first IP if multiple are present (client IP)
        ip |> String.split(",") |> List.first() |> String.trim()

      [] ->
        # Fallback to remote_ip
        format_ip_tuple(conn.remote_ip)
    end
  end

  @doc """
  Formats peer_data from Phoenix LiveView into a string IP address.

  Used in LiveView contexts where peer_data is available during mount/3.

  ## Examples

      iex> RsolvWeb.Helpers.IpHelper.format_peer_data(%{address: {192, 168, 1, 1}})
      "192.168.1.1"

      iex> RsolvWeb.Helpers.IpHelper.format_peer_data(nil)
      "unknown"

  """
  @spec format_peer_data(map() | nil) :: String.t()
  def format_peer_data(%{address: address}), do: format_ip_tuple(address)
  def format_peer_data(_), do: "unknown"

  @doc """
  Formats an IP address tuple into a dotted string.

  ## Examples

      iex> RsolvWeb.Helpers.IpHelper.format_ip_tuple({127, 0, 0, 1})
      "127.0.0.1"

      iex> RsolvWeb.Helpers.IpHelper.format_ip_tuple({0, 0, 0, 0, 0, 0, 0, 1})
      "::1"

  """
  @spec format_ip_tuple(tuple() | binary()) :: String.t()
  def format_ip_tuple({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"
  def format_ip_tuple(ip) when is_tuple(ip), do: :inet.ntoa(ip) |> to_string()
  def format_ip_tuple(ip) when is_binary(ip), do: ip
end
