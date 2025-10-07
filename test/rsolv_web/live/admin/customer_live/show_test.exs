defmodule RsolvWeb.Admin.CustomerLive.ShowTest do
  use RsolvWeb.ConnCase, async: false
  import Rsolv.TestHelpers, only: [unique_email: 0, unique_email: 1]

  import Phoenix.LiveViewTest
  import Rsolv.CustomersFixtures

  setup do
    staff = staff_customer_fixture()
    customer = customer_fixture(
      email: unique_email(),
      name: "Test Customer",
      subscription_plan: "pro",
      monthly_limit: 1000,
      current_usage: 250,
      active: true
    )
    %{staff: staff, customer: customer}
  end

  describe "Show" do
    test "shows customer info", %{conn: conn, staff: staff, customer: customer} do
      conn = log_in_customer(conn, staff)
      {:ok, _view, html} = live(conn, "/admin/customers/#{customer.id}")

      assert html =~ "Test Customer"
      assert html =~ customer.email
      assert html =~ "1000"
      assert html =~ "Active"
      assert html =~ "pro"
    end

    test "shows View link in customer list", %{conn: conn, staff: staff, customer: customer} do
      conn = log_in_customer(conn, staff)
      {:ok, view, html} = live(conn, "/admin/customers")

      # Check for View link in Actions column
      assert view |> element("a[href=\"/admin/customers/#{customer.id}\"]") |> has_element?()
      assert html =~ "View"
    end

    test "displays usage statistics", %{conn: conn, staff: staff, customer: customer} do
      conn = log_in_customer(conn, staff)
      {:ok, _view, html} = live(conn, "/admin/customers/#{customer.id}")

      # Check usage stats
      assert html =~ "Usage Statistics"
      assert html =~ "250 / 1000"
      assert html =~ "25%"
    end

    test "displays API keys", %{conn: conn, staff: staff, customer: customer} do
      # Create API keys for the customer
      {:ok, api_key1} = Rsolv.Customers.create_api_key(customer, %{name: "Production Key"})
      {:ok, api_key2} = Rsolv.Customers.create_api_key(customer, %{name: "Test Key"})

      conn = log_in_customer(conn, staff)
      {:ok, _view, html} = live(conn, "/admin/customers/#{customer.id}")

      assert html =~ "API Keys"
      assert html =~ "Production Key"
      assert html =~ "Test Key"
      assert html =~ String.slice(api_key1.key, 0, 8)
      assert html =~ String.slice(api_key2.key, 0, 8)
    end

    test "generates new API key and displays full key in modal", %{conn: conn, staff: staff, customer: customer} do
      conn = log_in_customer(conn, staff)
      {:ok, view, _html} = live(conn, "/admin/customers/#{customer.id}")

      # Click generate new key button
      view
      |> element("button[phx-click=\"generate-api-key\"]")
      |> render_click()

      html = render(view)

      # Check new key was generated with success message
      assert html =~ "API key generated successfully"
      assert html =~ "Copy it now - it won&#39;t be shown again!"

      # Check modal is displayed with full key
      assert html =~ "API Key Generated Successfully"
      assert html =~ "Copy this API key now"
      assert html =~ "rsolv_"

      # Check for copy button
      assert html =~ "Copy"
      assert html =~ "api-key-input"

      # Check for Done button
      assert view |> element("button[phx-click=\"close-api-key-modal\"]") |> has_element?()
    end

    test "closes API key modal when Done is clicked", %{conn: conn, staff: staff, customer: customer} do
      conn = log_in_customer(conn, staff)
      {:ok, view, _html} = live(conn, "/admin/customers/#{customer.id}")

      # Generate a new key
      view
      |> element("button[phx-click=\"generate-api-key\"]")
      |> render_click()

      # Modal should be visible
      html = render(view)
      assert html =~ "API Key Generated Successfully"

      # Click Done to close modal
      view
      |> element("button[phx-click=\"close-api-key-modal\"]")
      |> render_click()

      # Modal should be closed
      html = render(view)
      refute html =~ "API Key Generated Successfully"
      refute html =~ "Copy this API key now"
    end

    test "modal has proper fixed positioning classes", %{conn: conn, staff: staff, customer: customer} do
      conn = log_in_customer(conn, staff)
      {:ok, view, _html} = live(conn, "/admin/customers/#{customer.id}")

      # Generate a new key
      view
      |> element("button[phx-click=\"generate-api-key\"]")
      |> render_click()

      html = render(view)

      # Check for modal component with proper id
      assert html =~ "id=\"api-key-modal\""
      assert html =~ "relative z-50"

      # Check for backdrop with dark mode support
      assert html =~ "bg-zinc-50/90 dark:bg-gray-900/90 fixed inset-0"

      # Check for centering classes in LiveView modal component
      assert html =~ "flex min-h-full items-center justify-center"
    end

    test "shows back to customers link", %{conn: conn, staff: staff, customer: customer} do
      conn = log_in_customer(conn, staff)
      {:ok, view, html} = live(conn, "/admin/customers/#{customer.id}")

      # Check for back link
      assert view |> element("a[href=\"/admin/customers\"]") |> has_element?()
      assert html =~ "Back to Customers"
    end

    test "requires staff authentication", %{conn: conn, customer: customer} do
      regular_customer = customer_fixture(is_staff: false)

      # Try to access without login
      assert {:error, {:redirect, %{to: "/admin/login"}}} =
        live(conn, "/admin/customers/#{customer.id}")

      # Try to access as non-staff
      conn = log_in_customer(conn, regular_customer)
      assert {:error, {:redirect, %{to: "/"}}} =
        live(conn, "/admin/customers/#{customer.id}")
    end
  end
end