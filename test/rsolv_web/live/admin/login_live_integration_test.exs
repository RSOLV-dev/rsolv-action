defmodule RsolvWeb.Admin.LoginLiveIntegrationTest do
  use RsolvWeb.ConnCase
  import Phoenix.LiveViewTest
  alias Rsolv.Customers
  
  describe "admin login integration" do
    setup do
      # Create a staff user with password
      {:ok, staff_user} = Customers.create_customer(%{
        email: "admin@rsolv.com",
        name: "Admin User",
        is_staff: true,
        password: "TestPassword123!"
      })
      
      # Create a non-staff user
      {:ok, regular_user} = Customers.create_customer(%{
        email: "user@example.com",
        name: "Regular User",
        is_staff: false,
        password: "UserPassword123!"
      })
      
      %{staff_user: staff_user, regular_user: regular_user}
    end
    
    test "successful staff login redirects to auth endpoint", %{conn: conn, staff_user: _staff_user} do
      {:ok, view, _html} = live(conn, "/admin/login")
      
      # Fill in the form
      assert view
             |> element("form")
             |> render_change(%{email: "admin@rsolv.com", password: "TestPassword123!"})
      
      # Submit the form
      result = view
               |> element("form")
               |> render_submit(%{email: "admin@rsolv.com", password: "TestPassword123!"})
      
      # The view should redirect to /admin/auth with a token
      assert result =~ "redirect"
      
      # Follow the redirect
      assert_redirect(view, ~r"/admin/auth\?token=.+")
    end
    
    test "non-staff user login shows error", %{conn: conn, regular_user: _regular_user} do
      {:ok, view, _html} = live(conn, "/admin/login")
      
      # Fill in and submit the form
      view
      |> element("form")
      |> render_change(%{email: "user@example.com", password: "UserPassword123!"})
      
      html = view
             |> element("form")
             |> render_submit(%{email: "user@example.com", password: "UserPassword123!"})
      
      # Should show authorization error
      assert html =~ "You are not authorized to access the admin area"
      
      # Should stay on login page
      assert view |> element("#admin-login")
    end
    
    test "invalid credentials shows error", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/admin/login")
      
      # Fill in and submit with wrong password
      view
      |> element("form")
      |> render_change(%{email: "admin@rsolv.com", password: "WrongPassword"})
      
      html = view
             |> element("form")
             |> render_submit(%{email: "admin@rsolv.com", password: "WrongPassword"})
      
      # Should show invalid credentials error
      assert html =~ "Invalid email or password"
      
      # Should stay on login page
      assert view |> element("#admin-login")
    end
    
    test "form shows processing state during submission", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/admin/login")
      
      # Fill in the form
      view
      |> element("form")
      |> render_change(%{email: "admin@rsolv.com", password: "TestPassword123!"})
      
      # The button should change to "Signing in..." during processing
      # This is handled by the @processing assign in the template
      html = render(view)
      assert html =~ "Sign In"
      refute html =~ "Signing in..."
    end
    
    test "error messages are displayed correctly", %{conn: conn} do
      {:ok, view, html} = live(conn, "/admin/login")
      
      # Initially no error message
      refute html =~ "bg-red-50"
      
      # Submit with invalid credentials
      view
      |> element("form")
      |> render_submit(%{email: "nonexistent@example.com", password: "wrong"})
      
      # Error message should be displayed
      html = render(view)
      assert html =~ "bg-red-50"
      assert html =~ "Invalid email or password"
    end
  end
end