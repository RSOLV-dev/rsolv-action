defmodule RsolvWeb.Admin.ApiKeyLiveTest do
  use RsolvWeb.ConnCase, async: false

  import Phoenix.LiveViewTest
  import Rsolv.CustomersFixtures

  setup do
    staff = staff_customer_fixture()
    customer1 = customer_fixture(email: "customer1@example.com", name: "Customer 1")
    customer2 = customer_fixture(email: "customer2@example.com", name: "Customer 2")

    # Create API keys for testing
    {:ok, key1} = Rsolv.Customers.create_api_key(customer1, %{name: "Production Key"})
    {:ok, key2} = Rsolv.Customers.create_api_key(customer1, %{name: "Test Key"})
    {:ok, key3} = Rsolv.Customers.create_api_key(customer2, %{name: "Development Key"})

    %{
      staff: staff,
      customer1: customer1,
      customer2: customer2,
      key1: key1,
      key2: key2,
      key3: key3
    }
  end

  describe "Index" do
    test "lists all API keys across customers", %{
      conn: conn,
      staff: staff,
      key1: key1,
      key2: key2,
      key3: key3
    } do
      conn = log_in_customer(conn, staff)
      {:ok, _view, html} = live(conn, "/admin/api-keys")

      # Check that all API keys are displayed
      assert html =~ "API Keys Management"
      assert html =~ "Production Key"
      assert html =~ "Test Key"
      assert html =~ "Development Key"

      # Check that customer names are shown
      assert html =~ "Customer 1"
      assert html =~ "Customer 2"

      # Check that key prefixes are shown
      assert html =~ String.slice(key1.key, 0, 8)
      assert html =~ String.slice(key2.key, 0, 8)
      assert html =~ String.slice(key3.key, 0, 8)
    end

    test "shows status of API keys", %{conn: conn, staff: staff} do
      customer = customer_fixture()

      {:ok, active_key} =
        Rsolv.Customers.create_api_key(customer, %{name: "Active Key", active: true})

      {:ok, inactive_key} =
        Rsolv.Customers.update_api_key(
          Rsolv.Customers.create_api_key(customer, %{name: "Inactive Key"}) |> elem(1),
          %{active: false}
        )

      conn = log_in_customer(conn, staff)
      {:ok, _view, html} = live(conn, "/admin/api-keys")

      # Check for status indicators
      assert html =~ "Active Key"
      assert html =~ "Inactive Key"
    end

    test "allows editing API key", %{conn: conn, staff: staff, key1: key1} do
      conn = log_in_customer(conn, staff)
      {:ok, view, _html} = live(conn, "/admin/api-keys")

      # Click edit button
      view
      |> element("button[phx-click=\"edit\"][phx-value-id=\"#{key1.id}\"]")
      |> render_click()

      html = render(view)

      # Check edit modal opened
      assert html =~ "Edit API Key"
      assert html =~ "Production Key"
    end

    test "allows toggling API key status", %{conn: conn, staff: staff, key1: key1} do
      conn = log_in_customer(conn, staff)
      {:ok, view, _html} = live(conn, "/admin/api-keys")

      # Toggle status
      view
      |> element("button[phx-click=\"toggle-status\"][phx-value-id=\"#{key1.id}\"]")
      |> render_click()

      html = render(view)
      assert html =~ "API key status updated"
    end

    test "allows deleting API key with confirmation", %{conn: conn, staff: staff, key1: key1} do
      conn = log_in_customer(conn, staff)
      {:ok, view, _html} = live(conn, "/admin/api-keys")

      # Click delete button
      view
      |> element("button[phx-click=\"delete\"][phx-value-id=\"#{key1.id}\"]")
      |> render_click()

      html = render(view)

      # Check confirmation dialog
      assert html =~ "Are you sure"
      assert html =~ "Production Key"

      # Confirm deletion
      view
      |> element("button[phx-click=\"confirm-delete\"][phx-value-id=\"#{key1.id}\"]")
      |> render_click()

      html = render(view)
      assert html =~ "API key deleted successfully"
      refute html =~ "Production Key"
    end

    test "requires staff authentication", %{conn: conn} do
      regular_customer = customer_fixture(is_staff: false)

      # Try without login
      assert {:error, {:redirect, %{to: "/admin/login"}}} =
               live(conn, "/admin/api-keys")

      # Try as non-staff
      conn = log_in_customer(conn, regular_customer)

      assert {:error, {:redirect, %{to: "/"}}} =
               live(conn, "/admin/api-keys")
    end

    test "allows searching API keys", %{conn: conn, staff: staff} do
      conn = log_in_customer(conn, staff)
      {:ok, view, _html} = live(conn, "/admin/api-keys")

      # Search for Production
      view
      |> form("#search-form", %{search: "Production"})
      |> render_change()

      html = render(view)
      assert html =~ "Production Key"
      refute html =~ "Test Key"
      refute html =~ "Development Key"
    end
  end
end
