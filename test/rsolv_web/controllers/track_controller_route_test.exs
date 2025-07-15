defmodule RsolvWeb.TrackControllerRouteTest do
  use RsolvWeb.ConnCase, async: false
  
  describe "POST /api/track route" do
    test "route exists and responds to basic POST request", %{conn: conn} do
      # RED: This should pass but currently fails in staging (404)
      conn = post(conn, "/api/track", %{
        "type" => "test", 
        "data" => %{"test" => "validation"}
      })
      
      # Should get 201 Created, not 404 Not Found
      assert conn.status == 201
      assert json_response(conn, 201) == %{"success" => true}
    end
    
    test "route handles minimal payload", %{conn: conn} do
      conn = post(conn, "/api/track", %{"type" => "page_view"})
      
      assert conn.status == 201
      assert json_response(conn, 201) == %{"success" => true}
    end
    
    test "route processes different event types", %{conn: conn} do
      event_types = ["page_view", "form_submit", "conversion", "click"]
      
      for event_type <- event_types do
        conn = post(conn, "/api/track", %{"type" => event_type})
        assert conn.status == 201, "Failed for event type: #{event_type}"
      end
    end
    
    test "route uses API pipeline (no CSRF protection)", %{conn: conn} do
      # This request should work without CSRF token since it's in API pipeline
      conn = conn
      |> put_req_header("content-type", "application/json")
      |> post("/api/track", Jason.encode!(%{"type" => "test"}))
      
      assert conn.status == 201
      refute get_resp_header(conn, "x-csrf-token") |> Enum.any?()
    end
  end
  
  describe "route debugging" do
    test "verify route is registered in router", %{conn: conn} do
      # Check that the route exists in the router
      routes = Phoenix.Router.routes(RsolvWeb.Router)
      track_routes = Enum.filter(routes, fn route -> 
        route.path == "/api/track" and route.verb == :post
      end)
      
      assert length(track_routes) == 1, "Expected exactly one POST /api/track route"
      
      track_route = List.first(track_routes)
      assert track_route.plug == RsolvWeb.TrackController
      assert track_route.plug_opts == :track
    end
    
    test "verify controller module exists and is accessible", %{conn: conn} do
      # Verify the controller module can be loaded
      assert Code.ensure_loaded?(RsolvWeb.TrackController)
      assert function_exported?(RsolvWeb.TrackController, :track, 2)
    end
  end
end