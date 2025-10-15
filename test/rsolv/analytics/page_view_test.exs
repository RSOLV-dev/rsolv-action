defmodule Rsolv.Analytics.PageViewTest do
  use Rsolv.DataCase
  import Rsolv.TestHelpers, only: [unique_email: 0, unique_email: 1]
  alias Rsolv.Analytics.PageView
  alias Rsolv.Customers.Customer
  alias Rsolv.Repo

  describe "page_view schema" do
    test "should belong to customer, not user" do
      # Create a customer
      {:ok, customer} =
        Repo.insert(%Customer{
          name: "Test Company",
          email: unique_email()
        })

      # Create a page view associated with the customer
      page_view = %PageView{
        path: "/test-path",
        user_agent: "Test Agent",
        user_ip: "127.0.0.1",
        customer_id: customer.id
      }

      {:ok, inserted} = Repo.insert(page_view)

      # Load with association
      loaded = Repo.get!(PageView, inserted.id) |> Repo.preload(:customer)

      assert loaded.customer.id == customer.id
      assert loaded.customer.name == "Test Company"
    end

    test "page_view should have correct schema fields" do
      fields = PageView.__schema__(:fields)

      # Should have customer_id, not user_id
      assert :customer_id in fields
      refute :user_id in fields
    end

    test "page_view associations should reference Customer" do
      associations = PageView.__schema__(:associations)

      # Should have :customer association
      assert :customer in associations
      refute :user in associations

      # Verify the association type
      assert PageView.__schema__(:association, :customer).related == Rsolv.Customers.Customer
    end
  end
end
