defmodule RsolvWeb.DashboardControllerTest do
  use RsolvWeb.ConnCase

  setup do
    # Clear FunWithFlags cache before each test
    FunWithFlags.clear(:all)
    :ok
  end

  describe "dashboard access" do
    test "redirects to home when not authenticated", %{conn: conn} do
      conn = get(conn, ~p"/dashboard")
      assert html_response(conn, 401)
      assert conn.resp_headers |> Enum.any?(fn {k, v} -> k == "www-authenticate" && v =~ "Basic" end)
    end

    test "redirects to analytics when authenticated and feature flag enabled", %{conn: conn} do
      # Enable the admin_dashboard feature flag
      FunWithFlags.enable(:admin_dashboard)
      
      # Set up basic auth
      credentials = Base.encode64("admin:test_password")
      
      # Mock the admin password
      Application.put_env(:rsolv, :admin_password, "test_password")
      
      conn = 
        conn
        |> put_req_header("authorization", "Basic #{credentials}")
        |> get(~p"/dashboard")
      
      assert redirected_to(conn) == ~p"/dashboard/analytics"
    end

    test "redirects to home with error when feature flag disabled", %{conn: conn} do
      # Disable the admin_dashboard feature flag
      FunWithFlags.disable(:admin_dashboard)
      
      # Set up basic auth
      credentials = Base.encode64("admin:test_password")
      
      # Mock the admin password
      Application.put_env(:rsolv, :admin_password, "test_password")
      
      conn = 
        conn
        |> put_req_header("authorization", "Basic #{credentials}")
        |> get(~p"/dashboard")
      
      assert redirected_to(conn) == ~p"/"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "unavailable"
    end
  end

  describe "analytics dashboard access" do
    test "blocks access when metrics_dashboard flag is disabled", %{conn: conn} do
      # Enable admin_dashboard but disable metrics_dashboard
      FunWithFlags.enable(:admin_dashboard)
      FunWithFlags.disable(:metrics_dashboard)
      
      # Set up basic auth
      credentials = Base.encode64("admin:test_password")
      
      # Mock the admin password
      Application.put_env(:rsolv, :admin_password, "test_password")
      
      conn = 
        conn
        |> put_req_header("authorization", "Basic #{credentials}")
        |> get(~p"/dashboard/analytics")
      
      assert redirected_to(conn) == ~p"/"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "Metrics dashboard is currently unavailable"
    end

    test "allows access when both flags are enabled", %{conn: conn} do
      # Enable both flags
      FunWithFlags.enable(:admin_dashboard)
      FunWithFlags.enable(:metrics_dashboard)
      
      # Set up basic auth
      credentials = Base.encode64("admin:test_password")
      
      # Mock the admin password
      Application.put_env(:rsolv, :admin_password, "test_password")
      
      conn = 
        conn
        |> put_req_header("authorization", "Basic #{credentials}")
        |> get(~p"/dashboard/analytics")
      
      # Should render the live view
      assert html_response(conn, 200) =~ "data-phx-main"
    end
  end
end