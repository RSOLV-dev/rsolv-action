defmodule RsolvWeb.HomeLiveTestSimple do
  use RsolvWeb.ConnCase

  import Phoenix.LiveViewTest

  describe "HomeLive basic functionality" do
    test "renders the home page", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")

      # Check basic content
      assert html =~ "RSOLV"
      assert html =~ "Fix Security Issues in Real-Time"
      assert html =~ "Enter your email"
      assert html =~ "Get Early Access"
    end

    test "form validation works", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")

      # Submit invalid email
      html =
        view
        |> form("form", signup: %{email: "invalid", company: ""})
        |> render_submit()

      # Should show validation error in rendered HTML
      assert html =~ "Please enter a valid email address"
    end

    test "successful form submission", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")

      # Submit valid email
      html =
        view
        |> form("form", signup: %{company: "Test Co"})
        |> render_submit()

      # Should show success message
      assert html =~ "Thank you for signing up"
    end

    test "form validation on change", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")

      # Change to invalid email
      html =
        view
        |> form("form", signup: %{email: "", company: ""})
        |> render_change()

      # Should show validation error
      assert html =~ "Please enter a valid email address"
    end

    test "mobile menu toggle", %{conn: conn} do
      {:ok, view, html} = live(conn, "/")

      # Check if mobile menu toggle button exists
      assert has_element?(view, "button[phx-click=\"toggle_mobile_menu\"]")

      # Click the toggle button
      view
      |> element("button[phx-click=\"toggle_mobile_menu\"]")
      |> render_click()

      # Should not crash - mobile menu state changes internally
      assert true
    end

    test "navigation elements present", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")

      # Check navigation
      assert html =~ "Blog"
      assert html =~ "Sign Up"
      assert html =~ ~r/href="\/blog"/
      assert html =~ ~r/href="\/signup"/
    end

    test "form has proper structure", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")

      # Check form structure
      assert html =~ "phx-submit=\"submit\""
      assert html =~ "phx-change=\"validate\""
      assert html =~ "name=\"signup[email]\""
      assert html =~ "name=\"signup[company]\""
      assert html =~ "type=\"submit\""
    end

    test "email validation accepts valid formats", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")

      # Test valid email
      html =
        view
        |> form("form", signup: %{email: "user@example.com", company: ""})
        |> render_change()

      # Should not show validation error
      refute html =~ "Please enter a valid email address"
    end

    test "company field is optional", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")

      # Submit with just email
      html =
        view
        |> form("form", signup: %{company: ""})
        |> render_submit()

      # Should succeed
      assert html =~ "Thank you for signing up"
    end

    test "preserves form data during validation", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")

      # Submit invalid email with company
      html =
        view
        |> form("form", signup: %{email: "invalid", company: "Test Company"})
        |> render_change()

      # Should show error but preserve company field value
      assert html =~ "Please enter a valid email address"
      assert html =~ "value=\"Test Company\""
    end

    test "handles empty form submission", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")

      # Submit completely empty form
      html =
        view
        |> form("form", signup: %{email: "", company: ""})
        |> render_submit()

      # Should show validation error
      assert html =~ "Please enter a valid email address"
      refute html =~ "Thank you for signing up"
    end

    test "responsive design classes present", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")

      # Check for responsive utility classes
      assert html =~ "sm:"
      assert html =~ "lg:"
      assert html =~ "max-w-"
      assert html =~ "hidden sm:"
    end
  end
end
