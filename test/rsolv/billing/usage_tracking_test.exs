defmodule Rsolv.Billing.UsageTrackingTest do
  use ExUnit.Case, async: true

  alias Rsolv.Billing.UsageTracking

  describe "has_credits?/1" do
    test "returns true when credit_balance > 0" do
      assert UsageTracking.has_credits?(%{credit_balance: 5})
      assert UsageTracking.has_credits?(%{credit_balance: 1})
      assert UsageTracking.has_credits?(%{credit_balance: 100})
    end

    test "returns false when credit_balance is 0" do
      refute UsageTracking.has_credits?(%{credit_balance: 0})
    end

    test "returns false when credit_balance is negative" do
      refute UsageTracking.has_credits?(%{credit_balance: -1})
    end

    test "returns false when credit_balance is missing" do
      refute UsageTracking.has_credits?(%{})
      refute UsageTracking.has_credits?(%{other_field: "value"})
    end

    test "returns false for non-map input" do
      refute UsageTracking.has_credits?(nil)
      refute UsageTracking.has_credits?("string")
      refute UsageTracking.has_credits?(123)
    end
  end

  describe "has_billing_info?/1" do
    test "returns true when stripe_customer_id is present" do
      assert UsageTracking.has_billing_info?(%{stripe_customer_id: "cus_123"})
      assert UsageTracking.has_billing_info?(%{stripe_customer_id: "cus_abc"})
    end

    test "returns false when stripe_customer_id is nil" do
      refute UsageTracking.has_billing_info?(%{stripe_customer_id: nil})
    end

    test "returns false when stripe_customer_id is missing" do
      refute UsageTracking.has_billing_info?(%{})
      refute UsageTracking.has_billing_info?(%{other_field: "value"})
    end

    test "returns false for non-map input" do
      refute UsageTracking.has_billing_info?(nil)
      refute UsageTracking.has_billing_info?("string")
      refute UsageTracking.has_billing_info?(123)
    end
  end
end
