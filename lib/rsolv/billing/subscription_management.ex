defmodule Rsolv.Billing.SubscriptionManagement do
  @moduledoc """
  Manages customer subscriptions and plan changes.

  This module handles:
  - Subscribing customers to Pro plan
  - Canceling subscriptions (immediate or at period end)
  - Updating subscription status
  """

  alias Rsolv.Repo
  alias Rsolv.Billing.{StripeService, Subscription, Config}
  alias Rsolv.Customers.Customer

  import Ecto.Query, warn: false

  @doc """
  Subscribes a customer to the Pro plan.

  This function:
  1. Creates a Stripe subscription with the Pro price
  2. Updates customer record with subscription details
  3. Records the subscription in the subscriptions table

  The initial credit is added via webhook when invoice.paid is received.

  ## Examples

      iex> subscribe_to_pro(customer)
      {:ok, %Customer{subscription_type: "pro", ...}}

      iex> subscribe_to_pro(customer_without_payment_method)
      {:error, :no_payment_method}

  """
  def subscribe_to_pro(%Customer{has_payment_method: false}), do: {:error, :no_payment_method}

  def subscribe_to_pro(%Customer{} = customer) do
    pro_price_id = Config.pro_price_id()

    with {:ok, stripe_subscription} <-
           StripeService.create_subscription(customer.stripe_customer_id, pro_price_id) do
      create_subscription_records(customer, stripe_subscription)
    end
  end

  @doc """
  Cancels a customer's subscription.

  ## Parameters
  - customer: The customer whose subscription to cancel
  - at_period_end: If true, schedule cancellation at period end. If false, cancel immediately.

  ## Examples

      iex> cancel_subscription(customer, true)
      {:ok, %Customer{subscription_cancel_at_period_end: true, ...}}

      iex> cancel_subscription(customer, false)
      {:ok, %Customer{subscription_type: "pay_as_you_go", ...}}

  """
  def cancel_subscription(%Customer{stripe_subscription_id: nil}, _at_period_end) do
    {:error, :no_active_subscription}
  end

  def cancel_subscription(%Customer{} = customer, at_period_end) when is_boolean(at_period_end) do
    stripe_result =
      if at_period_end do
        StripeService.update_subscription(customer.stripe_subscription_id, %{
          cancel_at_period_end: true
        })
      else
        StripeService.cancel_subscription(customer.stripe_subscription_id)
      end

    with {:ok, _stripe_subscription} <- stripe_result do
      update_customer_after_cancellation(customer, at_period_end)
    end
  end

  # Private helper to create customer and subscription records atomically
  defp create_subscription_records(customer, stripe_subscription) do
    Ecto.Multi.new()
    |> Ecto.Multi.update(
      :customer,
      Customer.changeset(customer, %{
        stripe_subscription_id: stripe_subscription.id,
        subscription_type: "pro",
        subscription_state: stripe_subscription.status,
        subscription_cancel_at_period_end: false
      })
    )
    |> Ecto.Multi.insert(:subscription, fn %{customer: updated_customer} ->
      Subscription.changeset(%Subscription{}, %{
        customer_id: updated_customer.id,
        stripe_subscription_id: stripe_subscription.id,
        plan: "pro",
        status: stripe_subscription.status,
        current_period_start: DateTime.from_unix!(stripe_subscription.current_period_start),
        current_period_end: DateTime.from_unix!(stripe_subscription.current_period_end),
        cancel_at_period_end: false
      })
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{customer: updated_customer}} -> {:ok, updated_customer}
      {:error, _op, changeset, _changes} -> {:error, changeset}
    end
  end

  # Private helper to update customer record after cancellation
  defp update_customer_after_cancellation(customer, at_period_end) do
    updates =
      if at_period_end do
        %{subscription_cancel_at_period_end: true}
      else
        %{
          subscription_type: "pay_as_you_go",
          subscription_state: nil,
          stripe_subscription_id: nil,
          subscription_cancel_at_period_end: false
        }
      end

    customer
    |> Customer.changeset(updates)
    |> Repo.update()
  end
end
