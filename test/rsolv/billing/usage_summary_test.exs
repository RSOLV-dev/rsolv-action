defmodule Rsolv.Billing.UsageSummaryTest do
  use Rsolv.DataCase, async: true

  import Rsolv.CustomerFactory

  alias Rsolv.Billing
  alias Rsolv.Billing.CreditLedger

  describe "get_usage_summary/1" do
    test "returns credit balance and plan" do
      customer = insert(:customer, credit_balance: 50, subscription_type: "pro")

      assert {:ok, summary} = Billing.get_usage_summary(customer.id)

      assert summary.credit_balance == 50
      assert summary.subscription_type == "pro"
      assert summary.has_payment_method == false
      assert summary.warnings == []
    end

    test "includes recent transactions" do
      customer = insert(:customer, credit_balance: 10)

      # Create some transactions
      {:ok, %{customer: customer}} = CreditLedger.credit(customer, 5, "purchased", %{})

      {:ok, %{customer: customer}} =
        CreditLedger.consume(customer, 2, "consumed", %{"reason" => "test"})

      {:ok, %{customer: _customer}} =
        CreditLedger.credit(customer, 3, "adjustment", %{"reason" => "bonus"})

      assert {:ok, summary} = Billing.get_usage_summary(customer.id)

      assert length(summary.recent_transactions) == 3

      # Verify all transactions are present (order may vary due to timing)
      sources = Enum.map(summary.recent_transactions, & &1.source)
      amounts = Enum.map(summary.recent_transactions, & &1.amount)

      assert "adjustment" in sources
      assert "consumed" in sources
      assert "purchased" in sources
      assert 3 in amounts
      assert -2 in amounts
      assert 5 in amounts
    end

    test "limits to 10 most recent transactions" do
      customer = insert(:customer, credit_balance: 100)

      # Create 15 transactions
      Enum.reduce(1..15, customer, fn i, acc ->
        {:ok, %{customer: updated}} =
          CreditLedger.credit(acc, 1, "adjustment", %{"test_id" => i})

        updated
      end)

      assert {:ok, summary} = Billing.get_usage_summary(customer.id)

      assert length(summary.recent_transactions) == 10
    end

    test "calculates warning messages - low balance" do
      customer = insert(:customer, credit_balance: 3)

      assert {:ok, summary} = Billing.get_usage_summary(customer.id)

      assert "Low credit balance: 3 credits remaining" in summary.warnings
    end

    test "calculates warning messages - no credits, has payment" do
      # RFC-068: Use PAYG customer trait (0 credits, payment method attached)
      customer =
        :customer
        |> build()
        |> with_payg()
        |> insert()

      assert {:ok, summary} = Billing.get_usage_summary(customer.id)

      assert "No credits remaining. Your next fix will be charged." in summary.warnings
    end

    test "calculates warning messages - no credits, no payment" do
      customer = insert(:customer, credit_balance: 0, has_payment_method: false)

      assert {:ok, summary} = Billing.get_usage_summary(customer.id)

      assert "No credits remaining and no payment method on file. Add a payment method to continue using RSOLV." in summary.warnings
    end

    test "calculates warning messages - past due payment" do
      # RFC-068: Use delinquent customer trait (payment failed)
      customer =
        :customer
        |> build()
        |> with_pro_plan()
        |> with_past_due()
        |> insert()

      # Consume most credits to test warning
      {:ok, %{customer: customer}} = CreditLedger.consume(customer, 50, "consumed")

      assert {:ok, summary} = Billing.get_usage_summary(customer.id)

      assert "Payment failed. Please update your payment method." in summary.warnings
    end

    test "includes pricing summary" do
      customer = insert(:customer)

      assert {:ok, summary} = Billing.get_usage_summary(customer.id)

      assert summary.pricing.payg.price_cents == 2900
      assert summary.pricing.pro.overage_price_cents == 1500
      assert summary.pricing.pro.monthly_credits == 100
    end
  end
end
