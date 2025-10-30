defmodule Rsolv.Billing.CustomerSetupTest do
  use ExUnit.Case, async: true

  alias Rsolv.Billing.CustomerSetup
  alias Rsolv.Customers.Customer

  describe "add_payment_method/3" do
    test "returns error when billing_consent is false" do
      customer = %Customer{id: 1, email: "test@example.com"}

      assert {:error, :billing_consent_required} =
               CustomerSetup.add_payment_method(customer, "pm_test123", false)
    end
  end
end
