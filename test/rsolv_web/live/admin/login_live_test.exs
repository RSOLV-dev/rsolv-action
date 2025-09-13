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
        password: "Test@Password123!"
      })
      
      # Create a non-staff user for testing
      {:ok, regular_user} = Customers.create_customer(%{
        email: "user@example.com", 
        name: "Regular User",
        is_staff: false,
        password: "Test@Password123!"
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
      |> form("form", %{email: regular_user.email, password: "Test@Password123!"})
      |> render_submit()
      
      # Wait for async authentication
      Process.sleep(100)
      
      html = render(view)
      assert html =~ "You are not authorized to access the admin area"
    end
    
    test "redirects to auth controller for staff user", %{conn: conn, staff_user: staff_user} do
      {:ok, view, _html} = live(conn, ~p"/admin/login")
      
      view
      |> form("form", %{email: staff_user.email, password: "Test@Password123!"})
      |> render_submit()
      
      # Wait for async authentication
      Process.sleep(100)
      
      # Should redirect to auth controller with token
      {path, _flash} = assert_redirect(view)
      assert path =~ "/admin/auth?token="
    end
    
    test "root element has ID to prevent LiveView issues", %{conn: conn} do
      {:ok, view, html} = live(conn, ~p"/admin/login")
      
      # Elements should have IDs for proper LiveView DOM tracking
      assert element(view, "#admin-login")
      assert html =~ ~s(id="admin-login")
    end
    
    test "disables form while processing", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/admin/login")
      
      # Submit the form, which will trigger the processing state
      html = 
        view
        |> form("form", %{email: "test@example.com", password: "password"})
        |> render_submit()
      
      # The response from render_submit should show the processing state
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
        password: "Test@Password123!"
      })
      
      # Simulate the full login flow
      logged_in_conn = log_in_customer(conn, staff_user)
      
      %{conn: logged_in_conn, staff_user: staff_user}
    end
    
    test "maintains session after LiveView login", %{conn: conn, staff_user: staff_user} do
      # After login via LiveView -> AuthController flow,
      # the session should persist in Phoenix sessions
      
      # Should be able to access protected admin routes
      # First navigate to the customers list which we know exists
      {:ok, _view, html} = live(conn, ~p"/admin/customers")
      assert html =~ "Customers"
    end
    
    test "session works across multiple requests", %{conn: conn, staff_user: staff_user} do
      # First request to customers list
      {:ok, _view, html1} = live(conn, ~p"/admin/customers")
      assert html1 =~ "Customers"
      
      # Second request should also work, try the customer detail page
      # Since we don't have a customer ID, we'll just test the list page again
      conn2 = get(conn, ~p"/admin/customers")
      assert html_response(conn2, 200) =~ "Customers"
    end
    
    test "stores sessions in Mnesia CustomerSessions for distributed access", %{conn: _conn, staff_user: staff_user} do
      # Verify that LiveView login DOES store in CustomerSessions
      # This is critical for distributed session management across pods
      
      # Log in the staff user through the normal flow
      conn = build_conn()
      logged_in_conn = log_in_customer(conn, staff_user)
      
      # Check that CustomerSessions has the session stored for cross-pod access
      sessions = Rsolv.CustomerSessions.all_sessions()
      assert length(sessions) > 0
      
      # Verify the stored session belongs to the staff user
      assert Enum.any?(sessions, fn 
        {:customer_sessions_mnesia, _token, customer_id, _, _} -> 
          customer_id == staff_user.id
      end)
    end
  end
end