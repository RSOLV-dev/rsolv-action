defmodule RsolvWeb.Admin.DashboardControllerTest do
  use RsolvWeb.ConnCase, async: true
  import Rsolv.CustomersFixtures

  setup do
    staff = customer_fixture(%{email: "staff@rsolv.dev", is_staff: true})
    %{staff: staff}
  end

  describe "GET /admin/dashboard with metrics" do
    test "displays system metrics for staff", %{conn: conn, staff: staff} do
      conn = log_in_customer(conn, staff)
      conn = get(conn, ~p"/admin/dashboard")

      assert html = html_response(conn, 200)
      assert html =~ "System Metrics"
      assert html =~ "Total Customers"
      assert html =~ "Active API Keys"
      assert html =~ "Recent Activity"
    end

    test "shows customer count", %{conn: conn, staff: staff} do
      customer_fixture(%{email: "customer1@example.com"})
      customer_fixture(%{email: "customer2@example.com"})

      conn = log_in_customer(conn, staff)
      conn = get(conn, ~p"/admin/dashboard")

      html = html_response(conn, 200)
      # 3 total: 2 customers + 1 staff
      assert html =~ "3"
      assert html =~ "customers"
    end

    test "shows API key statistics", %{conn: conn, staff: staff} do
      customer = customer_fixture(%{email: "customer@example.com"})
      {:ok, _key1} = Rsolv.Customers.create_api_key(customer, %{name: "Key 1"})
      {:ok, _key2} = Rsolv.Customers.create_api_key(customer, %{name: "Key 2"})

      conn = log_in_customer(conn, staff)
      conn = get(conn, ~p"/admin/dashboard")

      html = html_response(conn, 200)
      assert html =~ "2"
      assert html =~ "API Keys"
    end

    test "shows system health status", %{conn: conn, staff: staff} do
      conn = log_in_customer(conn, staff)
      conn = get(conn, ~p"/admin/dashboard")

      html = html_response(conn, 200)
      assert html =~ "System Health"
      assert html =~ "Database"
      assert html =~ "Operational"
    end

    test "shows recent customer activity", %{conn: conn, staff: staff} do
      customer = customer_fixture(%{email: "recent@example.com"})
      {:ok, _key} = Rsolv.Customers.create_api_key(customer, %{name: "Recent Key"})

      conn = log_in_customer(conn, staff)
      conn = get(conn, ~p"/admin/dashboard")

      html = html_response(conn, 200)
      assert html =~ "Recent Activity"
      assert html =~ "recent@example.com"
      assert html =~ "created API key"
    end

    test "shows request volume metrics", %{conn: conn, staff: staff} do
      conn = log_in_customer(conn, staff)
      conn = get(conn, ~p"/admin/dashboard")

      html = html_response(conn, 200)
      assert html =~ "Request Volume"
      assert html =~ "Today"
      assert html =~ "This Week"
      assert html =~ "This Month"
    end

    test "requires staff authentication", %{conn: conn} do
      conn = get(conn, ~p"/admin/dashboard")
      assert redirected_to(conn) == ~p"/admin/login"
    end

    test "non-staff customers cannot access", %{conn: conn} do
      regular_customer = customer_fixture(%{email: "regular@example.com", is_staff: false})
      conn = log_in_customer(conn, regular_customer)

      conn = get(conn, ~p"/admin/dashboard")
      assert redirected_to(conn) == ~p"/"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "not authorized"
    end
  end
end