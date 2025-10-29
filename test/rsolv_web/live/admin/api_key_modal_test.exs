defmodule RsolvWeb.Admin.ApiKeyModalTest do
  use RsolvWeb.ConnCase, async: false
  import Rsolv.TestHelpers, only: [unique_email: 0, unique_email: 1]

  import Phoenix.LiveViewTest
  import Rsolv.CustomersFixtures

  setup do
    staff = staff_customer_fixture()
    customer = customer_fixture(name: "Test Customer")

    {:ok, %{record: api_key, raw_key: raw_key}} =
      Rsolv.Customers.create_api_key(customer, %{name: "Test Key"})

    %{staff: staff, customer: customer, api_key: api_key, raw_key: raw_key}
  end

  describe "Delete modal" do
    test "uses LiveView modal component with proper classes", %{
      conn: conn,
      staff: staff,
      api_key: api_key
    } do
      conn = log_in_customer(conn, staff)
      {:ok, view, _html} = live(conn, "/admin/api-keys")

      # Click delete button
      view
      |> element("button[phx-click=\"delete\"][phx-value-id=\"#{api_key.id}\"]")
      |> render_click()

      html = render(view)

      # Should use LiveView modal component structure
      assert html =~ "relative z-50"
      assert html =~ "bg-zinc-50/90 dark:bg-gray-900/90 fixed inset-0"
      assert html =~ "flex min-h-full items-center justify-center"

      # Should have proper dark mode support
      assert html =~ "bg-white dark:bg-gray-800"

      # Cancel button should have good contrast in dark mode
      assert html =~ "dark:bg-gray-700 dark:text-gray-100"
    end

    test "closes modal when Cancel is clicked", %{conn: conn, staff: staff, api_key: api_key} do
      conn = log_in_customer(conn, staff)
      {:ok, view, _html} = live(conn, "/admin/api-keys")

      # Open delete modal
      view
      |> element("button[phx-click=\"delete\"][phx-value-id=\"#{api_key.id}\"]")
      |> render_click()

      # Modal should be visible
      html = render(view)
      assert html =~ "Delete API Key"

      # Click Cancel
      view
      |> element("button[phx-click=\"cancel-delete\"]")
      |> render_click()

      # Modal should be closed
      html = render(view)
      refute html =~ "Delete API Key"
      refute html =~ "Are you sure you want to delete"
    end
  end

  describe "Edit modal" do
    test "uses LiveView modal component with proper classes", %{
      conn: conn,
      staff: staff,
      api_key: api_key
    } do
      conn = log_in_customer(conn, staff)
      {:ok, view, _html} = live(conn, "/admin/api-keys")

      # Click edit button
      view
      |> element("button[phx-click=\"edit\"][phx-value-id=\"#{api_key.id}\"]")
      |> render_click()

      html = render(view)

      # Should use LiveView modal component structure
      assert html =~ "relative z-50"
      assert html =~ "bg-zinc-50/90 dark:bg-gray-900/90 fixed inset-0"
      assert html =~ "flex min-h-full items-center justify-center"

      # Should have proper dark mode support
      assert html =~ "bg-white dark:bg-gray-800"

      # Cancel button should have good contrast in dark mode
      assert html =~ "dark:bg-gray-700 dark:text-gray-100"
    end

    test "closes modal when Cancel is clicked", %{conn: conn, staff: staff, api_key: api_key} do
      conn = log_in_customer(conn, staff)
      {:ok, view, _html} = live(conn, "/admin/api-keys")

      # Open edit modal
      view
      |> element("button[phx-click=\"edit\"][phx-value-id=\"#{api_key.id}\"]")
      |> render_click()

      # Modal should be visible
      html = render(view)
      assert html =~ "Edit API Key"

      # Click Cancel
      view
      |> element("button[phx-click=\"close_edit_modal\"]")
      |> render_click()

      # Modal should be closed
      html = render(view)
      refute html =~ "Edit API Key"
    end
  end
end
