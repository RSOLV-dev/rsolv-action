defmodule RsolvWeb.Helpers.IpHelperTest do
  use ExUnit.Case, async: true
  doctest RsolvWeb.Helpers.IpHelper

  alias RsolvWeb.Helpers.IpHelper

  describe "get_client_ip/1" do
    test "extracts IP from X-Forwarded-For header" do
      conn = %Plug.Conn{
        req_headers: [{"x-forwarded-for", "203.0.113.195, 70.41.3.18, 150.172.238.178"}],
        remote_ip: {127, 0, 0, 1}
      }

      assert IpHelper.get_client_ip(conn) == "203.0.113.195"
    end

    test "falls back to remote_ip when X-Forwarded-For not present" do
      conn = %Plug.Conn{
        req_headers: [],
        remote_ip: {192, 168, 1, 100}
      }

      assert IpHelper.get_client_ip(conn) == "192.168.1.100"
    end
  end

  describe "format_peer_data/1" do
    test "formats IPv4 address from peer_data" do
      peer_data = %{address: {10, 0, 0, 1}, port: 12345}
      assert IpHelper.format_peer_data(peer_data) == "10.0.0.1"
    end

    test "returns 'unknown' for nil peer_data" do
      assert IpHelper.format_peer_data(nil) == "unknown"
    end

    test "returns 'unknown' for empty map" do
      assert IpHelper.format_peer_data(%{}) == "unknown"
    end
  end

  describe "format_ip_tuple/1" do
    test "formats IPv4 tuple" do
      assert IpHelper.format_ip_tuple({192, 168, 0, 1}) == "192.168.0.1"
    end

    test "formats IPv6 tuple" do
      # IPv6 loopback
      assert IpHelper.format_ip_tuple({0, 0, 0, 0, 0, 0, 0, 1}) == "::1"
    end

    test "returns binary IP as-is" do
      assert IpHelper.format_ip_tuple("192.168.1.1") == "192.168.1.1"
    end
  end
end
