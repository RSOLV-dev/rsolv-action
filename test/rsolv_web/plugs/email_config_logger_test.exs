defmodule RsolvWeb.Plugs.EmailConfigLoggerTest do
  use ExUnit.Case, async: false
  use Plug.Test

  import ExUnit.CaptureLog

  alias RsolvWeb.Plugs.EmailConfigLogger

  describe "call/2" do
    test "logs email configuration on monitored paths" do
      conn = conn(:get, "/early-access")

      log =
        capture_log(fn ->
          EmailConfigLogger.call(conn, EmailConfigLogger.init([]))
        end)

      assert log =~ "[EMAIL CONFIG PLUG]"
      assert log =~ "Request to /early-access"
    end

    test "does not log on non-monitored paths" do
      conn = conn(:get, "/some-other-path")

      log =
        capture_log(fn ->
          EmailConfigLogger.call(conn, EmailConfigLogger.init([]))
        end)

      refute log =~ "[EMAIL CONFIG PLUG]"
    end

    test "returns conn unchanged" do
      conn = conn(:get, "/")

      capture_log(fn ->
        result_conn = EmailConfigLogger.call(conn, EmailConfigLogger.init([]))
        assert result_conn == conn
      end)
    end
  end
end
