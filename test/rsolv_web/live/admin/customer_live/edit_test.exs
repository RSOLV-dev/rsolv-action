defmodule RsolvWeb.Admin.CustomerLive.EditTest do
  use RsolvWeb.ConnCase, async: true
  
  import Phoenix.LiveViewTest
  import Rsolv.CustomersFixtures
  
  setup do
    staff = staff_customer_fixture()
    customer = customer_fixture(
      email: "edit@example.com",
      name: "Original Name",
      monthly_limit: 100
    )
    %{staff: staff, customer: customer}
  end
  
  describe "Edit" do
    test "renders edit form", %{conn: conn, staff: staff, customer: customer} do
      conn = log_in_customer(conn, staff)
      {:ok, view, _html} = live(conn, "/admin/customers/#{customer.id}")
      
      # Click edit button
      assert view |> element("button", "Edit") |> render_click() =~ "Edit Customer"
      
      # Check form fields are present
      assert has_element?(view, "input[name='customer[name]']")
      assert has_element?(view, "input[name='customer[email]']")
      assert has_element?(view, "input[name='customer[monthly_limit]']")
    end
    
    test "updates customer", %{conn: conn, staff: staff, customer: customer} do
      conn = log_in_customer(conn, staff)
      {:ok, view, _html} = live(conn, "/admin/customers/#{customer.id}")
      
      # Open edit modal
      view |> element("button", "Edit") |> render_click()
      
      # Submit form with updated data
      view
      |> form("#customer-form", customer: %{
        name: "Updated Name",
        email: "updated@example.com",
        monthly_limit: 200
      })
      |> render_submit()
      
      # Check for success message (no redirect in LiveView)
      assert render(view) =~ "Customer updated successfully"
      
      # Verify modal is closed
      refute render(view) =~ "Edit Customer"
      
      # Verify in database
      updated_customer = Rsolv.Customers.get_customer!(customer.id)
      assert updated_customer.name == "Updated Name"
      assert updated_customer.email == "updated@example.com"
      assert updated_customer.monthly_limit == 200
    end
    
    test "validates changes", %{conn: conn, staff: staff, customer: customer} do
      conn = log_in_customer(conn, staff)
      {:ok, view, _html} = live(conn, "/admin/customers/#{customer.id}")
      
      # Open edit modal
      view |> element("button", "Edit") |> render_click()
      
      # Try to submit form with invalid data
      view
      |> form("#customer-form", customer: %{
        name: "",
        email: "invalid-email",
        monthly_limit: -1
      })
      |> render_change()
      
      # Check validation errors appear
      html = render(view)
      assert html =~ "can&#39;t be blank"
      assert html =~ "must have the @ sign and no spaces"
      assert html =~ "must be greater than" or html =~ "Invalid value"
    end
    
    test "shows success message", %{conn: conn, staff: staff, customer: customer} do
      conn = log_in_customer(conn, staff)
      {:ok, view, _html} = live(conn, "/admin/customers/#{customer.id}")
      
      # Open edit modal
      view |> element("button", "Edit") |> render_click()
      
      # Submit valid form
      view
      |> form("#customer-form", customer: %{name: "Success Test"})
      |> render_submit()
      
      # Check for success message
      assert render(view) =~ "Customer updated successfully"
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