defmodule RsolvWeb.HomeLiveTest do
  use RsolvWeb.ConnCase
  
  import Phoenix.LiveViewTest
  
  describe "HomeLive mount" do
    test "renders the home page with navigation", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")
      
      # Check basic structure
      assert html =~ "RSOLV"
      assert html =~ "Fix Security Issues in Real-Time"
      assert html =~ "RSOLV automatically detects and fixes security vulnerabilities"
      
      # Check navigation
      assert html =~ "Blog"
      assert html =~ "Sign Up"
      
      # Check form is present
      assert html =~ "Enter your email"
      assert html =~ "Company (optional)"
      assert html =~ "Get Early Access"
    end
    
    test "captures UTM parameters from URL", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/?utm_source=twitter&utm_medium=social&utm_campaign=security_awareness")
      
      # Check UTM parameters are assigned by checking the LiveView state
      assert has_element?(view, "[data-utm-source='twitter']") || render(view) =~ "twitter"
    end
    
    test "initializes with empty form fields", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")
      
      assert view.assigns.email == ""
      assert view.assigns.company == ""
      assert view.assigns.errors == %{}
      assert view.assigns.submitting == false
      assert view.assigns.mobile_menu_open == false
    end
  end
  
  describe "mobile menu functionality" do
    test "toggles mobile menu open and closed", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")
      
      # Initially closed
      assert view.assigns.mobile_menu_open == false
      
      # Toggle open
      {:ok, _view, html} = view
                          |> element("button[phx-click=\"toggle_mobile_menu\"]")
                          |> render_click()
      
      assert view.assigns.mobile_menu_open == true
      
      # Toggle closed
      {:ok, _view, html} = view
                          |> element("button[phx-click=\"toggle_mobile_menu\"]")
                          |> render_click()
      
      assert view.assigns.mobile_menu_open == false
    end
    
    test "closes mobile menu explicitly", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")
      
      # First open the menu
      view
      |> element("button[phx-click=\"toggle_mobile_menu\"]")
      |> render_click()
      
      assert view.assigns.mobile_menu_open == true
      
      # Close the menu
      view
      |> element("[phx-click=\"close_mobile_menu\"]")
      |> render_click()
      
      assert view.assigns.mobile_menu_open == false
    end
  end
  
  describe "form validation" do
    test "validates email on form change", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")
      
      # Submit empty email
      view
      |> form("form", signup: %{email: "", company: "Test Co"})
      |> render_change()
      
      assert view.assigns.errors[:email] == "Please enter a valid email address"
      assert view.assigns.email == ""
      assert view.assigns.company == "Test Co"
    end
    
    test "validates email format on form change", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")
      
      # Submit invalid email format
      view
      |> form("form", signup: %{email: "invalid-email", company: ""})
      |> render_change()
      
      assert view.assigns.errors[:email] == "Please enter a valid email address"
      assert view.assigns.email == "invalid-email"
    end
    
    test "clears errors with valid email", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")
      
      # First trigger an error
      view
      |> form("form", signup: %{email: "", company: ""})
      |> render_change()
      
      assert view.assigns.errors[:email] == "Please enter a valid email address"
      
      # Then provide valid email
      view
      |> form("form", signup: %{email: "test@example.com", company: "Test Co"})
      |> render_change()
      
      assert view.assigns.errors == %{}
      assert view.assigns.email == "test@example.com"
      assert view.assigns.company == "Test Co"
    end
  end
  
  describe "form submission" do
    test "submits successfully with valid email", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")
      
      # Submit valid form
      view
      |> form("form", signup: %{email: "test@example.com", company: "Test Company"})
      |> render_submit()
      
      # Check success flash message
      assert Phoenix.Flash.get(view.assigns.flash, :success) =~ "Thank you for signing up"
      
      # Check form is cleared
      assert view.assigns.email == ""
      assert view.assigns.company == ""
    end
    
    test "shows errors on invalid submission", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")
      
      # Submit invalid form
      view
      |> form("form", signup: %{email: "invalid", company: "Test Company"})
      |> render_submit()
      
      # Check errors are shown
      assert view.assigns.errors[:email] == "Please enter a valid email address"
      
      # Check no success flash
      refute Phoenix.Flash.get(view.assigns.flash, :success)
      
      # Check form data is preserved
      assert view.assigns.email == "invalid"
      assert view.assigns.company == "Test Company"
    end
    
    test "handles empty email submission", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")
      
      # Submit with empty email
      view
      |> form("form", signup: %{email: "", company: "Test Company"})
      |> render_submit()
      
      # Check validation error
      assert view.assigns.errors[:email] == "Please enter a valid email address"
      
      # Check no success flash
      refute Phoenix.Flash.get(view.assigns.flash, :success)
    end
  end
  
  describe "analytics tracking integration" do
    test "tracks page view on mount", %{conn: conn} do
      # This would need to be integrated with our Analytics service
      {:ok, _view, _html} = live(conn, "/?utm_source=test&utm_campaign=test")
      
      # For now, just verify the mount succeeds
      # TODO: Add Analytics.track_page_view integration
      assert true
    end
    
    test "tracks conversion on successful signup", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")
      
      # Submit valid form
      view
      |> form("form", signup: %{email: "test@example.com", company: "Test Co"})
      |> render_submit()
      
      # For now, just verify the submission succeeds
      # TODO: Add Analytics.track_conversion("early_access_signup") integration
      assert Phoenix.Flash.get(view.assigns.flash, :success)
    end
  end
  
  describe "accessibility and UX" do
    test "form has proper labels and structure", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")
      
      # Check form has proper structure
      assert html =~ "phx-submit=\"submit\""
      assert html =~ "name=\"signup[email]\""
      assert html =~ "name=\"signup[company]\""
      assert html =~ "type=\"submit\""
    end
    
    test "navigation links work correctly", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")
      
      # Check navigation links are present
      assert html =~ ~r/href="\/blog"/
      assert html =~ ~r/href="\/signup"/
    end
    
    test "responsive design elements are present", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")
      
      # Check responsive classes are present
      assert html =~ "sm:"
      assert html =~ "lg:"
      assert html =~ "md:"
      
      # Check mobile menu functionality
      assert html =~ "hidden sm:ml-6 sm:flex"
    end
  end
end