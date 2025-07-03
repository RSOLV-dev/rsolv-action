defmodule RsolvWeb.DashboardControllerTest do
  use RsolvWeb.ConnCase

  describe "index/2" do
    test "redirects to home when accessed without authentication in production", %{conn: conn} do
      # Simulate production environment
      original_env = Application.get_env(:rsolv, :env)
      Application.put_env(:rsolv, :env, :prod)
      
      conn = get(conn, ~p"/dashboard")
      
      assert redirected_to(conn) == "/"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Access denied"
      
      # Restore environment
      Application.put_env(:rsolv, :env, original_env)
    end
    
    test "redirects to analytics dashboard with valid key in dev", %{conn: conn} do
      # Simulate dev environment
      original_env = Application.get_env(:rsolv, :env)
      Application.put_env(:rsolv, :env, :dev)
      
      # Set admin key
      Application.put_env(:rsolv, :admin_key, "test_admin_key")
      
      conn = get(conn, ~p"/dashboard?key=test_admin_key")
      
      assert redirected_to(conn) == "/dashboard/analytics"
      
      # Restore environment
      Application.put_env(:rsolv, :env, original_env)
    end
    
    test "denies access with invalid key in dev", %{conn: conn} do
      # Simulate dev environment
      original_env = Application.get_env(:rsolv, :env)
      Application.put_env(:rsolv, :env, :dev)
      
      # Set admin key
      Application.put_env(:rsolv, :admin_key, "test_admin_key")
      
      conn = get(conn, ~p"/dashboard?key=wrong_key")
      
      assert redirected_to(conn) == "/"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Access denied"
      
      # Restore environment
      Application.put_env(:rsolv, :env, original_env)
    end
  end
end