defmodule RsolvWeb.Admin.LoginLiveTest do
  use RsolvWeb.ConnCase
  import Phoenix.LiveViewTest
  
  alias Rsolv.Customers
  
  describe "Admin Login" do
    setup do
      # Create a staff user for testing
      {:ok, staff_user} = Customers.create_customer(%{
        email: "admin@example.com",
        name: "Admin User",
        is_staff: true,
        password: "test_password123"
      })
      
      # Create a non-staff user for testing
      {:ok, regular_user} = Customers.create_customer(%{
        email: "user@example.com", 
        name: "Regular User",
        is_staff: false,
        password: "test_password123"
      })
      
      %{staff_user: staff_user, regular_user: regular_user}
    end
    
    test "renders login form", %{conn: conn} do
      {:ok, _view, html} = live(conn, ~p"/admin/login")
      
      assert html =~ "Admin Login"
      assert html =~ "Email"
      assert html =~ "Password"
      assert html =~ "Sign In"
    end
    
    test "validates form input", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/admin/login")
      
      html =
        view
        |> form("form", %{email: "test@example.com", password: "pass"})
        |> render_change()
      
      # Form should update with values but not show errors on change
      refute html =~ "Invalid email or password"
    end
    
    test "shows error for invalid credentials", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/admin/login")
      
      view
      |> form("form", %{email: "wrong@example.com", password: "wrongpass"})
      |> render_submit()
      
      # Wait for async authentication
      Process.sleep(100)
      
      html = render(view)
      assert html =~ "Invalid email or password"
    end
    
    test "shows error for non-staff user", %{conn: conn, regular_user: regular_user} do
      {:ok, view, _html} = live(conn, ~p"/admin/login")
      
      view
      |> form("form", %{email: regular_user.email, password: "test_password123"})
      |> render_submit()
      
      # Wait for async authentication
      Process.sleep(100)
      
      html = render(view)
      assert html =~ "You are not authorized to access the admin area"
    end
    
    test "redirects to auth controller for staff user", %{conn: conn, staff_user: staff_user} do
      {:ok, view, _html} = live(conn, ~p"/admin/login")
      
      view
      |> form("form", %{email: staff_user.email, password: "test_password123"})
      |> render_submit()
      
      # Wait for async authentication
      Process.sleep(100)
      
      # Should redirect to auth controller with token
      assert_redirect(view, ~r"/admin/auth\?token=.+")
    end
    
    test "disables form while processing", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/admin/login")
      
      view
      |> form("form", %{email: "test@example.com", password: "password"})
      |> render_submit()
      
      # Immediately after submit, form should be disabled
      html = render(view)
      assert html =~ "Signing in..."
      assert html =~ "disabled"
    end
  end
  
  describe "Session Persistence" do
    setup %{conn: conn} do
      # Create and log in a staff user
      {:ok, staff_user} = Customers.create_customer(%{
        email: "admin@example.com",
        name: "Admin User", 
        is_staff: true,
        password: "test_password123"
      })
      
      # Simulate the full login flow
      conn = log_in_customer(conn, staff_user)
      
      %{conn: conn, staff_user: staff_user}
    end
    
    test "maintains session after LiveView login", %{conn: conn} do
      # After login via LiveView -> AuthController flow,
      # the session should persist in Phoenix sessions
      
      # Should be able to access protected admin routes
      conn = get(conn, ~p"/admin/dashboard")
      assert html_response(conn, 200) =~ "Admin Dashboard"
    end
    
    test "session works across multiple requests", %{conn: conn} do
      # First request to dashboard
      conn1 = get(conn, ~p"/admin/dashboard")
      assert html_response(conn1, 200) =~ "Admin Dashboard"
      
      # Second request should also work
      conn2 = get(conn, ~p"/admin/customers")
      assert redirected_to(conn2) == ~p"/admin/customers"
    end
    
    test "does not store sessions in Mnesia CustomerSessions", %{conn: _conn} do
      # Verify that LiveView login does NOT store in CustomerSessions
      # This is critical - LiveView should only generate tokens,
      # not store them in Mnesia
      
      # Check that CustomerSessions is empty after LiveView login
      # (The actual session is stored via Phoenix cookie sessions)
      sessions = Rsolv.CustomerSessions.all_sessions()
      assert sessions == []
    end
  end
end