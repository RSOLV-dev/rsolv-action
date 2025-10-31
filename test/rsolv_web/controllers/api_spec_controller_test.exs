defmodule RsolvWeb.ApiSpecControllerTest do
  use RsolvWeb.ConnCase, async: true

  describe "GET /api/openapi" do
    test "returns OpenAPI specification as JSON", %{conn: conn} do
      conn = get(conn, ~p"/api/openapi")

      assert conn.status == 200
      assert get_resp_header(conn, "content-type") == ["application/json; charset=utf-8"]

      # Just verify we got a response - the JSON encoding happens in the controller
      assert response(conn, 200)
    end
  end

  describe "GET /api/docs" do
    test "returns Swagger UI HTML", %{conn: conn} do
      conn = get(conn, ~p"/api/docs")

      assert conn.status == 200
      assert get_resp_header(conn, "content-type") == ["text/html; charset=utf-8"]

      html = response(conn, 200)
      assert html =~ "RSOLV API Documentation"
      assert html =~ "swagger-ui"
      assert html =~ "/api/openapi"
    end
  end
end
