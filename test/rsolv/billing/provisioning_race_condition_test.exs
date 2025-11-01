defmodule Rsolv.Billing.ProvisioningRaceConditionTest do
  @moduledoc """
  Tests for race condition prevention in payment method provisioning.

  This test suite validates that SELECT FOR UPDATE locks prevent double-crediting
  the billing_addition_bonus when concurrent requests attempt to add payment methods.

  See RFC-069 Wednesday for background on the race condition vulnerability.
  """
  use Rsolv.DataCase, async: false
  import Mox

  alias Rsolv.Billing
  alias Rsolv.Billing.CreditLedger
  alias Rsolv.Customers.Customer
  alias Rsolv.Repo

  setup :verify_on_exit!

  describe "concurrent payment method additions" do
    setup do
      # Create a trial customer without payment method
      customer =
        insert(:customer,
          stripe_customer_id: "cus_test123",
          credit_balance: 10,
          has_payment_method: false,
          stripe_payment_method_id: nil,
          subscription_type: "trial"
        )

      %{customer: customer}
    end

    test "concurrent requests only credit bonus once", %{customer: customer} do
      payment_method_id = "pm_test_card"
      initial_balance = customer.credit_balance

      # Mock Stripe API calls - expect exactly 2 calls (one from each concurrent request)
      # The second call will wait for the lock to release
      expect(Rsolv.Billing.StripeMock, :attach, 2, fn params ->
        assert params.payment_method == payment_method_id
        assert params.customer == customer.stripe_customer_id
        {:ok, %{id: payment_method_id, customer: customer.stripe_customer_id}}
      end)

      expect(Rsolv.Billing.StripeMock, :update, 2, fn stripe_customer_id, params ->
        assert stripe_customer_id == customer.stripe_customer_id
        assert params.invoice_settings.default_payment_method == payment_method_id
        {:ok, %{id: stripe_customer_id}}
      end)

      # Simulate concurrent requests using Task.async
      # Both requests will attempt to add payment method simultaneously
      task1 =
        Task.async(fn ->
          Billing.add_payment_method(customer, payment_method_id, true)
        end)

      task2 =
        Task.async(fn ->
          Billing.add_payment_method(customer, payment_method_id, true)
        end)

      # Wait for both tasks to complete
      result1 = Task.await(task1, 10_000)
      result2 = Task.await(task2, 10_000)

      # Both requests should succeed
      assert {:ok, updated_customer1} = result1
      assert {:ok, updated_customer2} = result2

      # Reload customer from database to get final state
      final_customer = Repo.get!(Customer, customer.id)

      # Critical assertion: Should only have +5 credits, not +10
      assert final_customer.credit_balance == initial_balance + 5,
             "Expected balance of #{initial_balance + 5}, got #{final_customer.credit_balance}"

      # Verify only ONE billing_addition_bonus transaction was recorded
      transactions = CreditLedger.list_transactions(final_customer)
      bonus_transactions = Enum.filter(transactions, &(&1.source == "trial_billing_added"))

      assert length(bonus_transactions) == 1,
             "Expected 1 bonus transaction, got #{length(bonus_transactions)}"

      [transaction] = bonus_transactions
      assert transaction.amount == 5
      assert transaction.balance_after == initial_balance + 5
    end

    test "SELECT FOR UPDATE lock causes second request to wait", %{customer: customer} do
      payment_method_id = "pm_test_card"
      initial_balance = customer.credit_balance

      # Track timing of lock acquisitions
      test_pid = self()

      # Mock Stripe calls
      expect(Rsolv.Billing.StripeMock, :attach, 2, fn params ->
        # Send timing message from within the transaction
        send(test_pid, {:stripe_attach_called, System.monotonic_time(:millisecond)})
        {:ok, %{id: params.payment_method, customer: params.customer}}
      end)

      expect(Rsolv.Billing.StripeMock, :update, 2, fn stripe_customer_id, _ ->
        {:ok, %{id: stripe_customer_id}}
      end)

      # Start first request
      task1 =
        Task.async(fn ->
          Billing.add_payment_method(customer, payment_method_id, true)
        end)

      # Small delay to ensure first request acquires lock first
      Process.sleep(50)

      # Start second request (will wait for lock)
      task2 =
        Task.async(fn ->
          Billing.add_payment_method(customer, payment_method_id, true)
        end)

      # Collect timing messages
      timing1 = receive do: ({:stripe_attach_called, t} -> t)
      timing2 = receive do: ({:stripe_attach_called, t} -> t)

      # Wait for both to complete
      Task.await(task1, 10_000)
      Task.await(task2, 10_000)

      # Verify requests were serialized (at least 10ms apart due to lock wait)
      time_diff = abs(timing2 - timing1)

      assert time_diff >= 10,
             "Expected requests to be serialized (>10ms apart), got #{time_diff}ms"

      # Reload and verify final state
      final_customer = Repo.get!(Customer, customer.id)
      assert final_customer.credit_balance == initial_balance + 5
    end

    test "second request sees has_payment_method: true and skips bonus", %{customer: customer} do
      payment_method_id = "pm_test_card"
      initial_balance = customer.credit_balance

      # Mock Stripe calls
      expect(Rsolv.Billing.StripeMock, :attach, 2, fn params ->
        {:ok, %{id: params.payment_method, customer: params.customer}}
      end)

      expect(Rsolv.Billing.StripeMock, :update, 2, fn stripe_customer_id, _ ->
        {:ok, %{id: stripe_customer_id}}
      end)

      # First request (should get bonus)
      assert {:ok, customer_after_first} =
               Billing.add_payment_method(customer, payment_method_id, true)

      assert customer_after_first.has_payment_method == true
      assert customer_after_first.credit_balance == initial_balance + 5

      # Second request with same customer (should NOT get bonus)
      # This simulates what happens when concurrent requests serialize
      assert {:ok, customer_after_second} =
               Billing.add_payment_method(customer_after_first, "pm_test_card_2", true)

      # Balance should still be +5, not +10
      assert customer_after_second.credit_balance == initial_balance + 5

      # Verify only ONE bonus transaction
      transactions = CreditLedger.list_transactions(customer_after_second)
      bonus_transactions = Enum.filter(transactions, &(&1.source == "trial_billing_added"))
      assert length(bonus_transactions) == 1
    end

    test "rapid sequential requests (manual double-click simulation)", %{customer: customer} do
      payment_method_id = "pm_test_card"
      initial_balance = customer.credit_balance

      # Mock Stripe calls for 3 attempts
      expect(Rsolv.Billing.StripeMock, :attach, 3, fn params ->
        {:ok, %{id: params.payment_method, customer: params.customer}}
      end)

      expect(Rsolv.Billing.StripeMock, :update, 3, fn stripe_customer_id, _ ->
        {:ok, %{id: stripe_customer_id}}
      end)

      # Simulate rapid button clicks (3 quick requests)
      task1 = Task.async(fn -> Billing.add_payment_method(customer, payment_method_id, true) end)
      task2 = Task.async(fn -> Billing.add_payment_method(customer, payment_method_id, true) end)
      task3 = Task.async(fn -> Billing.add_payment_method(customer, payment_method_id, true) end)

      # All should succeed
      assert {:ok, _} = Task.await(task1, 10_000)
      assert {:ok, _} = Task.await(task2, 10_000)
      assert {:ok, _} = Task.await(task3, 10_000)

      # Reload final state
      final_customer = Repo.get!(Customer, customer.id)

      # Should still only have +5 credits, not +15
      assert final_customer.credit_balance == initial_balance + 5

      # Verify only ONE bonus transaction
      transactions = CreditLedger.list_transactions(final_customer)
      bonus_transactions = Enum.filter(transactions, &(&1.source == "trial_billing_added"))
      assert length(bonus_transactions) == 1
    end
  end

  describe "trial customer without Stripe customer ID" do
    setup do
      # Create a trial customer without Stripe customer (common case)
      customer =
        insert(:customer,
          stripe_customer_id: nil,
          credit_balance: 5,
          has_payment_method: false,
          stripe_payment_method_id: nil,
          subscription_type: "trial"
        )

      %{customer: customer}
    end

    test "concurrent requests with Stripe customer creation only credit once", %{
      customer: customer
    } do
      payment_method_id = "pm_test_card"
      initial_balance = customer.credit_balance
      new_stripe_customer_id = "cus_newly_created"

      # Mock Stripe customer creation (should be called twice - once per concurrent request)
      expect(Rsolv.Billing.StripeMock, :create, 2, fn params ->
        assert params.email == customer.email
        {:ok, %{id: new_stripe_customer_id, email: params.email}}
      end)

      # Mock payment method attachment
      expect(Rsolv.Billing.StripeMock, :attach, 2, fn params ->
        assert params.payment_method == payment_method_id
        assert params.customer == new_stripe_customer_id
        {:ok, %{id: payment_method_id, customer: new_stripe_customer_id}}
      end)

      expect(Rsolv.Billing.StripeMock, :update, 2, fn stripe_customer_id, _ ->
        {:ok, %{id: stripe_customer_id}}
      end)

      # Concurrent requests
      task1 =
        Task.async(fn ->
          Billing.add_payment_method(customer, payment_method_id, true)
        end)

      task2 =
        Task.async(fn ->
          Billing.add_payment_method(customer, payment_method_id, true)
        end)

      # Wait for completion
      result1 = Task.await(task1, 10_000)
      result2 = Task.await(task2, 10_000)

      # Both should succeed
      assert {:ok, _} = result1
      assert {:ok, _} = result2

      # Reload customer
      final_customer = Repo.get!(Customer, customer.id)

      # Should have Stripe customer ID
      assert final_customer.stripe_customer_id == new_stripe_customer_id

      # Should only have +5 credits (not +10)
      assert final_customer.credit_balance == initial_balance + 5

      # Verify only ONE bonus transaction
      transactions = CreditLedger.list_transactions(final_customer)
      bonus_transactions = Enum.filter(transactions, &(&1.source == "trial_billing_added"))
      assert length(bonus_transactions) == 1
    end
  end

  describe "error handling with locks" do
    setup do
      customer =
        insert(:customer,
          stripe_customer_id: "cus_test123",
          credit_balance: 10,
          has_payment_method: false,
          subscription_type: "trial"
        )

      %{customer: customer}
    end

    test "lock is released on Stripe API error", %{customer: customer} do
      payment_method_id = "pm_test_card"

      # Mock Stripe failure on first attempt
      expect(Rsolv.Billing.StripeMock, :attach, fn _ ->
        {:error, %{message: "card_declined"}}
      end)

      # First request should fail and release lock
      assert {:error, _} = Billing.add_payment_method(customer, payment_method_id, true)

      # Mock success on second attempt
      expect(Rsolv.Billing.StripeMock, :attach, fn params ->
        {:ok, %{id: params.payment_method, customer: params.customer}}
      end)

      expect(Rsolv.Billing.StripeMock, :update, fn stripe_customer_id, _ ->
        {:ok, %{id: stripe_customer_id}}
      end)

      # Second request should succeed (proves lock was released)
      assert {:ok, updated_customer} =
               Billing.add_payment_method(customer, payment_method_id, true)

      assert updated_customer.has_payment_method == true
      assert updated_customer.credit_balance == customer.credit_balance + 5
    end
  end
end
