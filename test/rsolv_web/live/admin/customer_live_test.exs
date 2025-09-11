defmodule RsolvWeb.Admin.CustomerLiveTest do
  use RsolvWeb.ConnCase, async: true
  
  import Phoenix.LiveViewTest
  import Rsolv.CustomersFixtures
  
  setup do
    staff = staff_customer_fixture()
    %{staff: staff}
  end
  
  describe "Index" do
    test "mounts with customers", %{conn: conn, staff: staff} do
      # Create some test customers
      customer1 = customer_fixture(email: "test1@example.com", name: "Test Customer 1")
      customer2 = customer_fixture(email: "test2@example.com", name: "Test Customer 2")
      
      # Log in as staff
      conn = log_in_customer(conn, staff)
      
      # Navigate to the customer list LiveView
      {:ok, view, html} = live(conn, "/admin/customers")
      
      # Check that both customers appear in the table
      assert html =~ "Test Customer 1"
      assert html =~ "test1@example.com"
      assert html =~ "Test Customer 2"
      assert html =~ "test2@example.com"
      
      # Check that pagination info is present
      assert html =~ "Showing"
      assert html =~ "of"
    end
    
    test "paginates customers", %{conn: conn, staff: staff} do
      # Create 25 customers (more than one page)
      for i <- 1..25 do
        customer_fixture(
          email: "customer#{i}@example.com",
          name: "Customer #{i}"
        )
      end
      
      conn = log_in_customer(conn, staff)
      {:ok, view, html} = live(conn, "/admin/customers")
      
      # Default sort is inserted_at DESC, so newest customers appear first
      # We expect at least customers 25 down to 7 on the first page
      assert html =~ "Customer 25"
      assert html =~ "Customer 7"
      
      # Should show pagination info
      assert html =~ "Showing"
      
      # Navigate to page 2
      view
      |> element("a", "2")
      |> render_click()
      
      html = render(view)
      
      # Should show remaining customers including 1
      assert html =~ "Customer 1"
      refute html =~ "Customer 25"
    end
    
    test "filters by status", %{conn: conn, staff: staff} do
      active_customer = customer_fixture(
        email: "active@example.com",
        name: "Active Customer",
        active: true
      )
      
      inactive_customer = customer_fixture(
        email: "inactive@example.com",
        name: "Inactive Customer",
        active: false
      )
      
      conn = log_in_customer(conn, staff)
      {:ok, view, html} = live(conn, "/admin/customers")
      
      # Initially shows all customers
      assert html =~ "Active Customer"
      assert html =~ "Inactive Customer"
      
      # Filter by active status
      view
      |> form("#filter-form", %{status: "active"})
      |> render_change()
      
      html = render(view)
      assert html =~ "Active Customer"
      refute html =~ "Inactive Customer"
      
      # Filter by inactive status
      view
      |> form("#filter-form", %{status: "inactive"})
      |> render_change()
      
      html = render(view)
      refute html =~ "Active Customer"
      assert html =~ "Inactive Customer"
    end
    
    test "sorts by column", %{conn: conn, staff: staff} do
      customer_a = customer_fixture(email: "alpha@example.com", name: "Alpha")
      customer_z = customer_fixture(email: "zulu@example.com", name: "Zulu")
      
      conn = log_in_customer(conn, staff)
      {:ok, view, html} = live(conn, "/admin/customers")
      
      # Default sort should be by inserted_at desc (newest first)
      # Since customer_z was created after customer_a, it should appear first
      assert html =~ "Zulu"
      assert html =~ "Alpha"
      
      # Click name column to sort by name ascending
      view
      |> element("th[phx-click=\"sort\"][phx-value-field=\"name\"]")
      |> render_click()
      
      html = render(view)
      # When sorted by name asc, Alpha should come before Zulu
      assert html =~ ~r/Alpha.*Zulu/s
      
      # Click again to sort by name descending
      view
      |> element("th[phx-click=\"sort\"][phx-value-field=\"name\"]")
      |> render_click()
      
      html = render(view)
      # When sorted by name desc, Zulu should come before Alpha
      assert html =~ ~r/Zulu.*Alpha/s
    end
    
    test "requires staff authentication", %{conn: conn} do
      regular_customer = customer_fixture(is_staff: false)
      
      # Try to access without login
      assert {:error, {:redirect, %{to: "/admin/login"}}} = 
        live(conn, "/admin/customers")
      
      # Try to access as non-staff customer
      conn = log_in_customer(conn, regular_customer)
      assert {:error, {:redirect, %{to: "/"}}} = 
        live(conn, "/admin/customers")
    end
  end
  
  # Helper to log in a customer
  defp log_in_customer(conn, customer) do
    token = Rsolv.Customers.generate_customer_session_token(customer)
    
    conn
    |> Phoenix.ConnTest.init_test_session(%{})
    |> Plug.Conn.put_session(:customer_token, token)
  end
end