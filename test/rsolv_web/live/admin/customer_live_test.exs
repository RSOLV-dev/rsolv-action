defmodule RsolvWeb.Admin.CustomerLiveTest do
  use RsolvWeb.ConnCase, async: false
  
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

    test "shows edit button for each customer", %{conn: conn, staff: staff} do
      customer = customer_fixture(email: "edit@example.com", name: "Edit Me")

      conn = log_in_customer(conn, staff)
      {:ok, view, html} = live(conn, "/admin/customers")

      # Check for edit button in actions column
      assert html =~ "Edit"
      assert view |> element("a[phx-click=edit][phx-value-id=#{customer.id}]") |> has_element?()
    end

    test "opens edit modal when edit button clicked", %{conn: conn, staff: staff} do
      customer = customer_fixture(email: "edit@example.com", name: "Edit Me")

      conn = log_in_customer(conn, staff)
      {:ok, view, html} = live(conn, "/admin/customers")

      # Click edit button
      view
      |> element("a[phx-click=edit][phx-value-id=#{customer.id}]")
      |> render_click()

      html = render(view)

      # Check modal opened with customer data
      assert html =~ "Edit Customer"
      assert html =~ "edit@example.com"
      assert html =~ "Edit Me"
    end

    test "updates customer when edit form submitted", %{conn: conn, staff: staff} do
      customer = customer_fixture(email: "old@example.com", name: "Old Name")

      conn = log_in_customer(conn, staff)
      {:ok, view, _html} = live(conn, "/admin/customers")

      # Open edit modal
      view
      |> element("a[phx-click=edit][phx-value-id=#{customer.id}]")
      |> render_click()

      # Submit updated data
      view
      |> form("#customer-form", customer: %{
        name: "New Name",
        email: "new@example.com",
        active: false
      })
      |> render_submit()

      html = render(view)

      # Check customer was updated in the list
      assert html =~ "New Name"
      assert html =~ "new@example.com"
      refute html =~ "Old Name"
      refute html =~ "old@example.com"
    end

    test "shows new customer button", %{conn: conn, staff: staff} do
      conn = log_in_customer(conn, staff)
      {:ok, view, html} = live(conn, "/admin/customers")

      # Check for new customer button
      assert html =~ "New Customer"
      assert view |> element("button[phx-click=new]") |> has_element?()
    end

    test "opens new customer modal when button clicked", %{conn: conn, staff: staff} do
      conn = log_in_customer(conn, staff)
      {:ok, view, _html} = live(conn, "/admin/customers")

      # Click new customer button
      view
      |> element("button[phx-click=new]")
      |> render_click()

      html = render(view)

      # Check modal opened with empty form
      assert html =~ "New Customer"
      assert view |> element("#customer-form") |> has_element?()
    end

    test "creates new customer when form submitted", %{conn: conn, staff: staff} do
      conn = log_in_customer(conn, staff)
      {:ok, view, _html} = live(conn, "/admin/customers")

      # Open new customer modal
      view
      |> element("button[phx-click=new]")
      |> render_click()

      # Submit new customer data
      view
      |> form("#customer-form", customer: %{
        name: "Brand New Customer",
        email: "brand.new@example.com",
        password: "SecurePassword123!",
        active: true,
        subscription_plan: "Pro",
        monthly_limit: 5000
      })
      |> render_submit()

      html = render(view)

      # Check new customer appears in the list
      assert html =~ "Brand New Customer"
      assert html =~ "brand.new@example.com"
      assert html =~ "Pro"
    end

    test "shows delete button for each customer", %{conn: conn, staff: staff} do
      customer = customer_fixture(email: "delete@example.com", name: "Delete Me")

      conn = log_in_customer(conn, staff)
      {:ok, view, html} = live(conn, "/admin/customers")

      # Check for delete button in actions column
      assert html =~ "Delete"
      assert view |> element("button[phx-click=delete][phx-value-id=#{customer.id}]") |> has_element?()
    end

    test "shows confirmation dialog when delete clicked", %{conn: conn, staff: staff} do
      customer = customer_fixture(email: "delete@example.com", name: "Delete Me")

      conn = log_in_customer(conn, staff)
      {:ok, view, _html} = live(conn, "/admin/customers")

      # Click delete button
      view
      |> element("button[phx-click=\"delete\"][phx-value-id=\"#{customer.id}\"]")
      |> render_click()

      html = render(view)

      # Check confirmation dialog appeared
      assert html =~ "Are you sure"
      assert html =~ "Delete Me"
      assert html =~ "This action cannot be undone"
    end

    test "deletes customer when confirmed", %{conn: conn, staff: staff} do
      customer = customer_fixture(email: "delete@example.com", name: "Delete Me")

      conn = log_in_customer(conn, staff)
      {:ok, view, _html} = live(conn, "/admin/customers")

      # Click delete button
      view
      |> element("button[phx-click=\"delete\"][phx-value-id=\"#{customer.id}\"]")
      |> render_click()

      # Confirm deletion
      view
      |> element("button[phx-click=confirm-delete][phx-value-id=#{customer.id}]")
      |> render_click()

      html = render(view)

      # Check customer was removed from the list
      refute html =~ "Delete Me"
      refute html =~ "delete@example.com"
    end
  end

end