defmodule Rsolv.BillingTest do
  @moduledoc """
  Tests for Billing context, focusing on RFC-066 Week 3 implementation.

  TDD methodology: RED-GREEN-REFACTOR
  These tests are written BEFORE implementation of track_fix_deployed/2.
  """
  use Rsolv.DataCase, async: true

  alias Rsolv.Billing
  alias Rsolv.Billing.{FixAttempt, CreditLedger}
  alias Rsolv.Customers.Customer
  alias Rsolv.Repo

  import Rsolv.CustomersFixtures
  import Mox

  describe "track_fix_deployed/2" do
    setup do
      # Create a fix attempt for testing
      fix_attempt =
        %FixAttempt{
          id: 1,
          github_org: "test-org",
          repo_name: "test-repo",
          pr_number: 42,
          status: "merged"
        }
        |> Repo.insert!()

      %{fix: fix_attempt}
    end

    @tag :red
    test "consumes credit when customer has available credits", %{fix: fix} do
      # RED: This test should FAIL initially
      # Arrange: Customer with credits
      customer = customer_fixture(%{credit_balance: 10})

      # Act: Track fix deployment
      result = Billing.track_fix_deployed(customer, fix)

      # Assert: Credit consumed, balance decreased
      assert {:ok, %{customer: updated_customer, transaction: transaction}} = result
      assert updated_customer.credit_balance == 9
      assert transaction.amount == -1
      assert transaction.source == "fix_deployed"
      assert transaction.metadata["fix_id"] == fix.id
    end

    @tag :red
    test "blocks when customer has no credits and no billing info", %{fix: fix} do
      # RED: This test should FAIL initially
      # Arrange: Customer with no credits, no billing
      customer =
        customer_fixture(%{
          credit_balance: 0,
          stripe_customer_id: nil,
          has_payment_method: false
        })

      # Act: Try to track fix deployment
      result = Billing.track_fix_deployed(customer, fix)

      # Assert: Blocked with error
      assert {:error, :no_billing_info} = result
    end

    @tag :red
    test "charges PAYG rate ($29) when customer out of credits", %{fix: fix} do
      # RED: This test should FAIL initially
      # Arrange: PAYG customer with no credits but has billing
      customer =
        customer_fixture(%{
          credit_balance: 0,
          subscription_type: "pay_as_you_go",
          stripe_customer_id: "cus_test_payg",
          stripe_payment_method_id: "pm_test_visa",
          has_payment_method: true
        })

      # Mock Stripe charge creation
      expect(Rsolv.Billing.StripeMock, :create, fn params ->
        # $29 in cents
        assert params.amount == 2900
        assert params.customer == "cus_test_payg"
        {:ok, %{id: "ch_test_123", amount: 2900}}
      end)

      # Act: Track fix deployment (should charge $29)
      result = Billing.track_fix_deployed(customer, fix)

      # Assert: Charged, credited, consumed
      assert {:ok, :charged_and_consumed} = result

      # Verify customer reloaded and credit consumed
      reloaded_customer = Repo.get!(Customer, customer.id)
      assert reloaded_customer.credit_balance == 0

      # Verify credit and debit transactions created
      transactions = CreditLedger.list_transactions(reloaded_customer)
      assert length(transactions) == 2

      # Should have credit transaction (+1 from purchase)
      credit_txn = Enum.find(transactions, fn t -> t.amount > 0 end)
      assert credit_txn.amount == 1
      assert credit_txn.source == "purchased"
      assert credit_txn.metadata["amount_cents"] == 2900

      # Should have debit transaction (-1 from consumption)
      debit_txn = Enum.find(transactions, fn t -> t.amount < 0 end)
      assert debit_txn.amount == -1
      assert debit_txn.source == "fix_deployed"
    end

    @tag :red
    test "charges discounted Pro rate ($15) for Pro additional fixes", %{fix: fix} do
      # RED: This test should FAIL initially
      # Arrange: Pro customer out of included credits
      customer =
        customer_fixture(%{
          credit_balance: 0,
          subscription_type: "pro",
          subscription_state: "active",
          stripe_customer_id: "cus_test_pro",
          stripe_payment_method_id: "pm_test_visa",
          stripe_subscription_id: "sub_test_active",
          has_payment_method: true
        })

      # Mock Stripe charge creation
      expect(Rsolv.Billing.StripeMock, :create, fn params ->
        # $15 in cents
        assert params.amount == 1500
        assert params.customer == "cus_test_pro"
        {:ok, %{id: "ch_test_123", amount: 1500}}
      end)

      # Act: Track fix deployment (should charge $15 Pro overage)
      result = Billing.track_fix_deployed(customer, fix)

      # Assert: Charged at Pro rate
      assert {:ok, :charged_and_consumed} = result

      # Verify credit transaction at Pro overage price ($15)
      reloaded_customer = Repo.get!(Customer, customer.id)
      transactions = CreditLedger.list_transactions(reloaded_customer)

      credit_txn = Enum.find(transactions, fn t -> t.amount > 0 end)
      assert credit_txn.metadata["amount_cents"] == 1500
    end

    @tag :red
    test "creates credit then consumes after charge", %{fix: fix} do
      # RED: This test should FAIL initially
      # Arrange: PAYG customer with no credits
      customer =
        customer_fixture(%{
          credit_balance: 0,
          subscription_type: "pay_as_you_go",
          stripe_customer_id: "cus_test_123",
          has_payment_method: true
        })

      # Mock Stripe charge creation
      expect(Rsolv.Billing.StripeMock, :create, fn params ->
        # $29 PAYG rate
        assert params.amount == 2900
        assert params.customer == "cus_test_123"
        {:ok, %{id: "ch_test_123", amount: 2900}}
      end)

      # Act: Track fix deployment
      Billing.track_fix_deployed(customer, fix)

      # Assert: Atomic transaction created both credit and debit
      transactions = CreditLedger.list_transactions(Repo.get!(Customer, customer.id))
      assert length(transactions) == 2

      # Verify both transactions exist (order may vary when timestamps are identical)
      consume_txn = Enum.find(transactions, fn t -> t.source == "fix_deployed" end)
      credit_txn = Enum.find(transactions, fn t -> t.source == "purchased" end)

      assert consume_txn.amount == -1
      assert consume_txn.metadata["fix_id"] == fix.id

      assert credit_txn.amount == 1
    end

    @tag :red
    test "reloads customer before checking balance", %{fix: fix} do
      # RED: This test should FAIL initially
      # This test ensures we don't have stale data issues
      customer = customer_fixture(%{credit_balance: 5})

      # Simulate another process consuming credits
      CreditLedger.consume(customer, 4, "consumed", %{})

      # Our stale customer struct still shows 5 credits, but DB has 1
      assert customer.credit_balance == 5

      # Act: track_fix_deployed should reload and see actual balance (1 credit)
      result = Billing.track_fix_deployed(customer, fix)

      # Assert: Should succeed with 1 credit (not use stale 5)
      assert {:ok, %{customer: updated_customer, transaction: _transaction}} = result
      assert updated_customer.credit_balance == 0
    end
  end

  describe "helper predicates (for track_fix_deployed implementation)" do
    @tag :red
    test "has_credits?/1 returns true when credit_balance > 0" do
      # RED: These helpers don't exist yet
      customer = customer_fixture(%{credit_balance: 5})
      assert Billing.has_credits?(customer)
    end

    @tag :red
    test "has_credits?/1 returns false when credit_balance = 0" do
      customer = customer_fixture(%{credit_balance: 0})
      refute Billing.has_credits?(customer)
    end

    @tag :red
    test "has_billing_info?/1 returns true when stripe_customer_id present" do
      customer =
        customer_fixture(%{
          stripe_customer_id: "cus_test_123",
          has_payment_method: true
        })

      assert Billing.has_billing_info?(customer)
    end

    @tag :red
    test "has_billing_info?/1 returns false when no stripe_customer_id" do
      customer =
        customer_fixture(%{
          stripe_customer_id: nil,
          has_payment_method: false
        })

      refute Billing.has_billing_info?(customer)
    end
  end
end
