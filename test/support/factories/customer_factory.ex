defmodule Rsolv.CustomerFactory do
  @moduledoc """
  Factory for creating billing test customers with various states.

  This factory supports creating customers in different billing states
  for comprehensive testing of the billing system (RFCs 065-068).

  ## RFC-068 Factory Traits

  The following traits implement the test customer states specified in RFC-068:

  | Trait                | Credits | Payment Method | Subscription | Use Case                    |
  |----------------------|---------|----------------|--------------|------------------------------|
  | `with_trial_credits` | 5       | No             | Trial        | New signup, no billing      |
  | `with_payg`          | 0       | Yes            | PAYG         | Pay-per-fix customer        |
  | `with_pro_plan`      | 60      | Yes            | Pro/Active   | Active Pro subscription     |
  | `with_past_due`      | Varies  | Yes            | Past Due     | Payment failed (delinquent) |

  ## Usage

      # Basic customer (no credits, no billing)
      insert(:customer)

      # RFC-068 Trait: Trial customer (5 credits, no payment method)
      insert(:customer) |> with_trial_credits()

      # RFC-068 Trait: PAYG customer (0 credits, payment method attached)
      insert(:customer) |> with_payg()

      # RFC-068 Trait: Pro customer (60 credits, active subscription)
      insert(:customer) |> with_pro_plan()

      # RFC-068 Trait: Delinquent customer (payment failed)
      insert(:customer) |> with_pro_plan() |> with_past_due()

      # Additional helpers
      insert(:customer) |> with_billing_added()  # 10 credits (5 + 5 bonus)
      insert(:customer) |> with_pro_plan_partial_usage()  # 45 credits remaining

  ## Credit System (RFC-066)

  - Signup: 5 credits
  - Billing added: +5 credits (total 10)
  - Pro plan payment: +60 credits (total 60 for billing cycle)

  All traits now properly set the `credit_balance` field in addition to legacy fields
  for backward compatibility during the transition to RFC-066's unified credit system.

  See RFC-066 for complete credit system details.
  """

  use ExMachina.Ecto, repo: Rsolv.Repo

  alias Rsolv.Customers.Customer
  alias Rsolv.Billing.CreditTransaction

  @doc """
  Base customer factory.

  Creates a customer with default trial state (no credits, no billing).
  """
  def customer_factory do
    %Customer{
      email: sequence(:email, &"customer-#{&1}@test.example.com"),
      name: "Test Customer",
      trial_fixes_used: 0,
      trial_fixes_limit: 5,
      subscription_type: "trial",
      subscription_state: "active",
      rollover_fixes: 0,
      fixes_used_this_month: 0,
      fixes_quota_this_month: 0,
      has_payment_method: false,
      stripe_customer_id: nil,
      payment_method_added_at: nil,
      trial_expired_at: nil,
      monthly_limit: 100,
      current_usage: 0,
      active: true,
      is_staff: false,
      metadata: %{},
      credit_balance: 0
    }
  end

  @doc """
  Customer with trial credits (5 credits on signup).

  This represents a newly signed up customer who has not yet
  added billing information.

  RFC-068 Trait: Trial customer with 5 credits, no payment method
  """
  def with_trial_credits(customer) do
    %{
      customer
      | credit_balance: 5,
        trial_fixes_limit: 5,
        trial_fixes_used: 0,
        subscription_type: "trial",
        subscription_state: "active",
        has_payment_method: false,
        stripe_customer_id: nil,
        stripe_payment_method_id: nil
    }
  end

  @doc """
  Customer with billing added (10 total credits: 5 signup + 5 billing).

  This represents a trial customer who has added payment information
  and received the bonus 5 credits.
  """
  def with_billing_added(customer) do
    %{
      customer
      | credit_balance: 10,
        trial_fixes_limit: 10,
        trial_fixes_used: 0,
        stripe_customer_id: "cus_test_#{System.unique_integer([:positive])}",
        stripe_payment_method_id: "pm_test_#{System.unique_integer([:positive])}",
        has_payment_method: true,
        payment_method_added_at: DateTime.utc_now(),
        billing_consent_given: true,
        billing_consent_at: DateTime.utc_now()
    }
  end

  @doc """
  Customer with Pro plan (60 credits from subscription).

  This represents a customer with an active Pro subscription.

  RFC-068 Trait: Pro customer with 60 credits, active subscription
  """
  def with_pro_plan(customer) do
    %{
      customer
      | credit_balance: 60,
        trial_fixes_limit: 0,
        trial_fixes_used: 0,
        fixes_quota_this_month: 60,
        fixes_used_this_month: 0,
        rollover_fixes: 0,
        subscription_type: "pro",
        subscription_state: "active",
        stripe_customer_id: "cus_test_#{System.unique_integer([:positive])}",
        stripe_payment_method_id: "pm_test_#{System.unique_integer([:positive])}",
        stripe_subscription_id: "sub_test_#{System.unique_integer([:positive])}",
        has_payment_method: true,
        payment_method_added_at: DateTime.add(DateTime.utc_now(), -30, :day),
        billing_consent_given: true,
        billing_consent_at: DateTime.add(DateTime.utc_now(), -30, :day)
    }
  end

  @doc """
  Customer with Pro plan and some credits used (15 used, 45 remaining).

  Useful for testing mid-month usage scenarios.
  """
  def with_pro_plan_partial_usage(customer) do
    customer
    |> with_pro_plan()
    |> then(&%{&1 | credit_balance: 45, fixes_used_this_month: 15})
  end

  @doc """
  Customer with Pro plan that is past due.

  This represents a customer whose payment failed.

  RFC-068 Trait: Delinquent customer (payment failed)
  """
  def with_past_due(customer) do
    %{
      customer
      | subscription_state: "past_due",
        # Preserve existing credits but prevent new charges
        credit_balance: customer.credit_balance || 0
    }
  end

  @doc """
  Customer with Pro plan scheduled for cancellation.

  This represents a customer who cancelled but retains Pro benefits
  until the end of the billing period (cancel_at_period_end).
  """
  def with_cancel_scheduled(customer) do
    %{customer | subscription_state: "active", metadata: %{"cancel_at_period_end" => true}}
  end

  @doc """
  Customer with cancelled Pro plan (credits preserved).

  This represents a customer who immediately cancelled and their
  remaining credits are preserved.
  """
  def with_cancelled_pro(customer) do
    %{
      customer
      | subscription_state: "canceled",
        subscription_type: "trial",
        # Preserve remaining credits as trial credits
        trial_fixes_limit: customer.fixes_quota_this_month - customer.fixes_used_this_month,
        trial_fixes_used: 0,
        fixes_quota_this_month: 0,
        fixes_used_this_month: 0
    }
  end

  @doc """
  Customer with expired trial and no billing.

  This represents a customer who exhausted their trial credits
  without adding payment information.
  """
  def with_expired_trial(customer) do
    %{
      customer
      | trial_fixes_used: 5,
        trial_fixes_limit: 5,
        trial_expired_at: DateTime.add(DateTime.utc_now(), -1, :day)
    }
  end

  @doc """
  Customer on PAYG (Pay As You Go) plan.

  This represents a customer with billing added who pays per fix
  instead of subscribing to Pro.

  RFC-068 Trait: PAYG customer with 0 credits, payment method attached
  """
  def with_payg(customer) do
    %{
      customer
      | credit_balance: 0,
        trial_fixes_limit: 0,
        trial_fixes_used: 0,
        subscription_type: "payg",
        subscription_state: "active",
        stripe_customer_id: "cus_test_#{System.unique_integer([:positive])}",
        stripe_payment_method_id: "pm_test_#{System.unique_integer([:positive])}",
        has_payment_method: true,
        payment_method_added_at: DateTime.utc_now(),
        billing_consent_given: true,
        billing_consent_at: DateTime.utc_now()
    }
  end

  @doc """
  Customer with rollover credits from previous month.

  This represents a Pro customer who has unused credits from
  the previous billing period (up to 10 allowed).
  """
  def with_rollover_credits(customer, rollover_amount \\ 10) do
    customer
    |> with_pro_plan()
    |> Map.put(:rollover_fixes, rollover_amount)
  end

  @doc """
  Staff customer for internal testing.
  """
  def with_staff_access(customer) do
    %{customer | is_staff: true, email: sequence(:staff_email, &"staff-#{&1}@rsolv.dev")}
  end

  @doc """
  Base credit transaction factory.

  Creates a transaction with default values and auto-generated timestamps.
  Override any field including inserted_at/updated_at for time-based testing.

  ## Usage

      # Basic transaction with auto-generated timestamps
      insert(:credit_transaction, customer: customer)

      # Transaction with explicit timestamp for ordering tests (avoids sleep)
      insert(:credit_transaction,
        customer: customer,
        inserted_at: ~U[2025-01-01 12:00:00Z]
      )

  ## Timestamp Testing

  To test time-based ordering without sleep, use explicit timestamps:

      base_time = ~U[2025-01-01 12:00:00Z]

      t1 = insert(:credit_transaction,
        customer: customer,
        inserted_at: DateTime.add(base_time, 0, :second)
      )

      t2 = insert(:credit_transaction,
        customer: customer,
        inserted_at: DateTime.add(base_time, 60, :second)
      )

      # t2 will be ordered before t1 (newest first)

  """
  def credit_transaction_factory do
    %CreditTransaction{
      customer: build(:customer),
      amount: 10,
      balance_after: 100,
      source: "test",
      metadata: %{},
      inserted_at: DateTime.utc_now(),
      updated_at: DateTime.utc_now()
    }
  end
end
