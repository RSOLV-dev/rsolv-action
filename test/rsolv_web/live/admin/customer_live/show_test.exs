defmodule RsolvWeb.Admin.CustomerLive.ShowTest do
  use RsolvWeb.ConnCase, async: true
  
  import Phoenix.LiveViewTest
  import Rsolv.CustomersFixtures
  
  setup do
    staff = staff_customer_fixture()
    %{staff: staff}
  end
  
  describe "Show" do
    test "shows customer info", %{conn: conn, staff: staff} do
      customer = customer_fixture(
        email: "test@example.com",
        name: "Test Customer",
        monthly_limit: 1000,
        active: true
      )
      
      conn = log_in_customer(conn, staff)
      {:ok, _view, html} = live(conn, "/admin/customers/#{customer.id}")
      
      assert html =~ "Test Customer"
      assert html =~ "test@example.com"
      assert html =~ "1000"
      assert html =~ "Active"
    end
    
    test "displays API keys", %{conn: conn, staff: staff} do
      customer = customer_fixture(
        email: "test@example.com",
        name: "Test Customer"
      )
      
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
  end
  
end