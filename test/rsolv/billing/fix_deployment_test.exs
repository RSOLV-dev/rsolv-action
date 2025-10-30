defmodule Rsolv.Billing.FixDeploymentTest do
  use Rsolv.DataCase, async: true

  import Mox

  alias Rsolv.Billing
  alias Rsolv.Billing.CreditLedger
  alias Rsolv.Customers

  # Make mocks available in tests
  setup :verify_on_exit!

  describe "track_fix_deployed/2 - credit consumption" do
    setup do
      # Create customer with credits
      customer = insert(:customer, credit_balance: 0)

      # Add credits
      {:ok, %{customer: customer}} =
        CreditLedger.credit(customer, 10, "trial_signup", %{})

      fix = %{id: "fix_123"}
      %{customer: customer, fix: fix}
    end

    # RED PHASE: Test credit consumption when credits are available
    test "consumes credit when available", %{customer: customer, fix: fix} do
      initial_balance = customer.credit_balance
      assert initial_balance == 10

      assert {:ok, %{customer: updated_customer, transaction: transaction}} =
               Billing.track_fix_deployed(customer, fix)

      assert updated_customer.credit_balance == initial_balance - 1
      assert transaction.amount == -1
      assert transaction.source == "fix_deployed"
      assert transaction.metadata["fix_id"] == fix.id
    end

    # RED PHASE: Test blocking when no credits and no billing info
    test "blocks when no credits and no billing", %{fix: fix} do
      broke_customer =
        insert(:customer,
          credit_balance: 0,
          stripe_customer_id: nil,
          has_payment_method: false
        )

      assert broke_customer.credit_balance == 0
      assert is_nil(broke_customer.stripe_customer_id)

      assert {:error, :no_billing_info} = Billing.track_fix_deployed(broke_customer, fix)
    end
  end

  describe "track_fix_deployed/2 - charging" do
    setup do
      # Create customer with billing but no credits
      customer =
        insert(:customer,
          credit_balance: 0,
          stripe_customer_id: "cus_test_123",
          stripe_payment_method_id: "pm_test_123",
          has_payment_method: true,
          subscription_type: "pay_as_you_go"
        )

      fix = %{id: "fix_456"}
      %{customer: customer, fix: fix}
    end

    # RED PHASE: Test charging PAYG rate when out of credits
    test "charges PAYG rate ($29) when out of credits", %{customer: customer, fix: fix} do
      assert customer.credit_balance == 0
      assert customer.subscription_type == "pay_as_you_go"

      # Mock Stripe charge creation
      expect(Rsolv.Billing.StripeChargeMock, :create, fn params ->
        assert params.customer == customer.stripe_customer_id
        assert params.amount == 2900
        assert params.currency == "usd"

        {:ok,
         %{
           id: "ch_test_#{System.unique_integer([:positive])}",
           amount: 2900,
           currency: "usd",
           customer: customer.stripe_customer_id,
           status: "succeeded"
         }}
      end)

      assert {:ok, :charged_and_consumed} = Billing.track_fix_deployed(customer, fix)

      # Verify customer still at 0 balance (charged 1 credit, consumed 1 credit)
      reloaded = Customers.get_customer!(customer.id)
      assert reloaded.credit_balance == 0

      # Verify transaction history shows purchase + consumption
      # Note: list_credit_transactions returns in DESC order (newest first)
      transactions = Billing.list_credit_transactions(customer.id)
      assert length(transactions) == 2

      [purchase_txn, consume_txn] = Enum.sort_by(transactions, & &1.inserted_at, DateTime)

      assert purchase_txn.source == "purchased"
      assert purchase_txn.amount == 1
      # $29.00
      assert purchase_txn.metadata["amount_cents"] == 2900

      assert consume_txn.source == "fix_deployed"
      assert consume_txn.amount == -1
      assert consume_txn.metadata["fix_id"] == fix.id
    end

    # RED PHASE: Test charging Pro discounted rate when out of credits
    test "charges discounted rate ($15) for Pro additional", %{fix: fix} do
      pro_customer =
        insert(:customer,
          credit_balance: 0,
          stripe_customer_id: "cus_pro_123",
          stripe_payment_method_id: "pm_pro_123",
          stripe_subscription_id: "sub_pro_123",
          has_payment_method: true,
          subscription_type: "pro",
          subscription_state: "active"
        )

      assert pro_customer.credit_balance == 0
      assert pro_customer.subscription_type == "pro"

      # Mock Stripe charge creation for Pro customer
      expect(Rsolv.Billing.StripeChargeMock, :create, fn params ->
        assert params.customer == pro_customer.stripe_customer_id
        assert params.amount == 1500
        assert params.currency == "usd"

        {:ok,
         %{
           id: "ch_test_pro_#{System.unique_integer([:positive])}",
           amount: 1500,
           currency: "usd",
           customer: pro_customer.stripe_customer_id,
           status: "succeeded"
         }}
      end)

      assert {:ok, :charged_and_consumed} = Billing.track_fix_deployed(pro_customer, fix)

      # Verify transaction
      transactions = Billing.list_credit_transactions(pro_customer.id)
      [purchase, _consume] = Enum.sort_by(transactions, & &1.inserted_at, DateTime)

      # $15.00
      assert purchase.metadata["amount_cents"] == 1500
    end

    # RED PHASE: Test complete charge-credit-consume flow
    test "credits then consumes after charge", %{customer: customer, fix: fix} do
      # Mock Stripe charge creation
      expect(Rsolv.Billing.StripeChargeMock, :create, fn params ->
        {:ok,
         %{
           id: "ch_test_#{System.unique_integer([:positive])}",
           amount: params.amount,
           currency: "usd",
           customer: params.customer,
           status: "succeeded"
         }}
      end)

      assert {:ok, :charged_and_consumed} = Billing.track_fix_deployed(customer, fix)

      # Verify final state: 0 balance (1 added, 1 removed)
      reloaded = Customers.get_customer!(customer.id)
      assert reloaded.credit_balance == 0

      # Verify atomicity: both transactions exist
      transactions = Billing.list_credit_transactions(customer.id)
      assert length(transactions) == 2

      sources = Enum.map(transactions, & &1.source)
      assert "purchased" in sources
      assert "fix_deployed" in sources
    end
  end

  describe "track_fix_deployed/2 - error handling" do
    # RED PHASE: Test Stripe error handling
    test "handles Stripe payment failure gracefully" do
      customer =
        insert(:customer,
          credit_balance: 0,
          stripe_customer_id: "cus_fail_123",
          stripe_payment_method_id: "pm_card_declined",
          has_payment_method: true,
          subscription_type: "pay_as_you_go"
        )

      fix = %{id: "fix_789"}

      # Mock Stripe to return card_declined error
      expect(Rsolv.Billing.StripeChargeMock, :create, fn _params ->
        {:error,
         %Stripe.Error{
           code: :card_declined,
           message: "Your card was declined.",
           source: :stripe,
           user_message: "Your card was declined."
         }}
      end)

      assert {:error, %Stripe.Error{code: :card_declined}} =
               Billing.track_fix_deployed(customer, fix)

      # Verify no credit changes occurred
      reloaded = Customers.get_customer!(customer.id)
      assert reloaded.credit_balance == 0
      assert Billing.list_credit_transactions(customer.id) == []
    end
  end
end
