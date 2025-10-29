defmodule Rsolv.Billing.PricingTest do
  use Rsolv.DataCase, async: true

  alias Rsolv.Billing.Pricing

  describe "calculate_charge_amount/1" do
    test "uses configured PAYG price" do
      customer = insert(:customer, subscription_type: "pay_as_you_go")

      assert Pricing.calculate_charge_amount(customer) == 2900
    end

    test "uses configured Pro price" do
      customer = insert(:customer, subscription_type: "pro")

      assert Pricing.calculate_charge_amount(customer) == 1500
    end

    test "defaults to PAYG for unknown subscription types" do
      customer = insert(:customer, subscription_type: "unknown")

      assert Pricing.calculate_charge_amount(customer) == 2900
    end

    test "defaults to PAYG for nil subscription type" do
      customer = insert(:customer, subscription_type: nil)

      assert Pricing.calculate_charge_amount(customer) == 2900
    end
  end

  describe "pricing accessors" do
    test "payg_price_cents/0 returns configured value" do
      assert Pricing.payg_price_cents() == 2900
    end

    test "pro_price_cents/0 returns configured value" do
      assert Pricing.pro_price_cents() == 1500
    end
  end

  describe "summary/0" do
    test "returns pricing summary with formatted values" do
      summary = Pricing.summary()

      assert summary.payg.price_cents == 2900
      assert summary.payg.price_display == "$29.00"

      assert summary.pro.overage_price_cents == 1500
      assert summary.pro.overage_display == "$15.00"
      assert summary.pro.monthly_credits == 100
    end
  end
end
