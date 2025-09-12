defmodule RsolvWeb.Admin.CustomerLiveSimpleTest do
  use RsolvWeb.ConnCase, async: false
  
  import Phoenix.LiveViewTest
  import Rsolv.CustomersFixtures
  
  setup do
    staff = staff_customer_fixture()
    %{staff: staff}
  end
  
  describe "Basic LiveView" do
    test "mounts and displays customers", %{conn: conn, staff: staff} do
      # Create test customers
      customer_fixture(email: "test1@example.com", name: "Test Customer 1")
      customer_fixture(email: "test2@example.com", name: "Test Customer 2")
      
      # Log in as staff
      conn = log_in_customer(conn, staff)
      
      # Navigate to the customer list LiveView
      {:ok, _view, html} = live(conn, "/admin/customers")
      
      # Check that customers appear
      assert html =~ "Test Customer 1"
      assert html =~ "test1@example.com"
      assert html =~ "Test Customer 2"
      assert html =~ "test2@example.com"
      
      # Check that basic UI elements are present
      assert html =~ "Customers"  # Page title
      assert html =~ "Showing"     # Pagination info
    end
    
    test "requires staff authentication", %{conn: conn} do
      regular_customer = customer_fixture(is_staff: false)
      
      # Try to access without login - should redirect to login
      assert {:error, {:redirect, %{to: "/admin/login"}}} = 
        live(conn, "/admin/customers")
      
      # Try to access as non-staff customer - should redirect away
      conn = log_in_customer(conn, regular_customer)
      assert {:error, {:redirect, %{to: "/"}}} = 
        live(conn, "/admin/customers")
    end
  end
  
end