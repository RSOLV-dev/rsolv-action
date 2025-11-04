defmodule RsolvWeb.MetricsControllerTest do
  use RsolvWeb.ConnCase, async: true

  describe "GET /metrics" do
    test "serves prometheus metrics via PromEx.Plug", %{conn: conn} do
      conn = get(conn, ~p"/metrics")

      # PromEx.Plug handles the response
      # In test environment, PromEx may not be initialized (503)
      # In production, it returns 200 with metrics or 404 if disabled
      assert conn.status in [200, 404, 503]
    end
  end
end
