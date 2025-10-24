defmodule Rsolv.CustomerFactory do
  @moduledoc """
  Factory for creating billing test customers with various states.

  This factory supports creating customers in different billing states
  for comprehensive testing of the billing system (RFCs 065-068).

  ## Usage

      # Basic customer
      insert(:customer)

      # Customer with trial credits (5 credits on signup)
      insert(:customer) |> with_trial_credits()

      # Customer with billing added (5 signup + 5 billing = 10 credits)
      insert(:customer) |> with_billing_added()

      # Customer with Pro plan (60 credits from subscription)
      insert(:customer) |> with_pro_plan()

      # Customer with past due subscription
      insert(:customer) |> with_pro_plan() |> with_past_due()

  ## Credit System

  - Signup: 5 credits
  - Billing added: +5 credits (total 10)
  - Pro plan payment: +60 credits (total 60 for billing cycle)

  See RFC-066 for complete credit system details.
  """

  use ExMachina.Ecto, repo: Rsolv.Repo

  alias Rsolv.Customers.Customer

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
      subscription_plan: "trial",
      subscription_status: "active",
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
      metadata: %{}
    }
  end

  @doc """
  Customer with trial credits (5 credits on signup).

  This represents a newly signed up customer who has not yet
  added billing information.
  """
  def with_trial_credits(customer) do
    %{customer | trial_fixes_limit: 5, trial_fixes_used: 0}
  end

  @doc """
  Customer with billing added (10 total credits: 5 signup + 5 billing).

  This represents a trial customer who has added payment information
  and received the bonus 5 credits.
  """
  def with_billing_added(customer) do
    %{
      customer
      | trial_fixes_limit: 10,
        trial_fixes_used: 0,
        stripe_customer_id: "cus_test_#{System.unique_integer([:positive])}",
        has_payment_method: true,
        payment_method_added_at: DateTime.utc_now()
    }
  end

  @doc """
  Customer with Pro plan (60 credits from subscription).

  This represents a customer with an active Pro subscription.
  """
  def with_pro_plan(customer) do
    %{
      customer
      | trial_fixes_limit: 0,
        trial_fixes_used: 0,
        fixes_quota_this_month: 60,
        fixes_used_this_month: 0,
        rollover_fixes: 0,
        subscription_plan: "pro",
        subscription_status: "active",
        stripe_customer_id: "cus_test_#{System.unique_integer([:positive])}",
        has_payment_method: true,
        payment_method_added_at: DateTime.add(DateTime.utc_now(), -30, :day)
    }
  end

  @doc """
  Customer with Pro plan and some credits used (15 used, 45 remaining).

  Useful for testing mid-month usage scenarios.
  """
  def with_pro_plan_partial_usage(customer) do
    customer
    |> with_pro_plan()
    |> Map.put(:fixes_used_this_month, 15)
  end

  @doc """
  Customer with Pro plan that is past due.

  This represents a customer whose payment failed.
  """
  def with_past_due(customer) do
    %{customer | subscription_status: "past_due"}
  end

  @doc """
  Customer with Pro plan scheduled for cancellation.

  This represents a customer who cancelled but retains Pro benefits
  until the end of the billing period (cancel_at_period_end).
  """
  def with_cancel_scheduled(customer) do
    %{customer | subscription_status: "active", metadata: %{"cancel_at_period_end" => true}}
  end

  @doc """
  Customer with cancelled Pro plan (credits preserved).

  This represents a customer who immediately cancelled and their
  remaining credits are preserved.
  """
  def with_cancelled_pro(customer) do
    %{
      customer
      | subscription_status: "canceled",
        subscription_plan: "trial",
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
  """
  def with_payg(customer) do
    %{
      customer
      | trial_fixes_limit: 0,
        trial_fixes_used: 0,
        subscription_plan: "payg",
        subscription_status: "active",
        stripe_customer_id: "cus_test_#{System.unique_integer([:positive])}",
        has_payment_method: true,
        payment_method_added_at: DateTime.utc_now()
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
end
