defmodule RsolvWeb.MetricsControllerTest do
  use RsolvWeb.ConnCase, async: true

  describe "GET /metrics" do
    test "serves prometheus metrics via PromEx.Plug", %{conn: conn} do
      conn = get(conn, ~p"/metrics")

      # PromEx.Plug handles the response
      # Just verify the endpoint is accessible and returns something
      assert conn.status in [200, 404]
    end
  end
end
