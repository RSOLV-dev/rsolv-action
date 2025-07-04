defmodule RsolvWeb.UnifiedRoutingTest do
  use RsolvWeb.ConnCase
  
  describe "unified routing" do
    test "both API and web routes work", %{conn: conn} do
      # Test API routes
      conn = get(conn, "/api/v1/patterns")
      assert json_response(conn, 200)
      
      # Test web routes
      conn = get(build_conn(), "/")
      assert html_response(conn, 200)
    end
    
    test "health check endpoint works", %{conn: conn} do
      conn = get(conn, "/health")
      assert json_response(conn, 200)
    end
    
    test "early access page is accessible", %{conn: conn} do
      conn = get(conn, "/signup")
      assert html_response(conn, 200)
    end
    
    test "blog routes are accessible", %{conn: conn} do
      # Enable blog feature flag for this test
      :ok = FunWithFlags.enable(:blog)
      
      conn = get(conn, "/blog")
      assert html_response(conn, 200)
    end
  end
end