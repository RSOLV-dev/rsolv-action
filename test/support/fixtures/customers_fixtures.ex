defmodule Rsolv.CustomersFixtures do
  @moduledoc """
  This module defines test helpers for creating
  entities via the `Rsolv.Customers` context.
  """

  alias Rsolv.Customers

  @doc """
  Generate a unique customer email.
  """
  def unique_customer_email, do: "customer#{System.unique_integer()}@example.com"

  @doc """
  Get the valid customer password for testing.
  """
  def valid_customer_password, do: "ValidPassword123!"

  @doc """
  Generate a customer.
  """
  def customer_fixture(attrs \\ %{}) do
    {:ok, customer} =
      attrs
      |> Enum.into(%{
        email: unique_customer_email(),
        name: "Test Customer",
        password: "ValidPassword123!",
        is_staff: false
      })
      |> Customers.register_customer()

    customer
  end

  @doc """
  Generate a staff customer.
  """
  def staff_customer_fixture(attrs \\ %{}) do
    {:ok, customer} =
      attrs
      |> Enum.into(%{
        email: unique_customer_email(),
        name: "Staff Member",
        password: "StaffPassword123!",
        is_staff: true
      })
      |> Customers.register_customer()

    customer
  end

  @doc """
  Extract customer token from the session.
  """
  def extract_customer_token(fun) do
    {:ok, captured_conn} = fun.(&"[TOKEN]#{&1}[TOKEN]")
    [_, token | _] = String.split(captured_conn.resp_body, "[TOKEN]")
    token
  end

  # Billing-related fixtures (RFC-068)

  @doc """
  Generate a Stripe subscription fixture.
  """
  def subscription_fixture(attrs \\ %{}) do
    Enum.into(attrs, %{
      id: "sub_test_#{System.unique_integer([:positive])}",
      object: "subscription",
      customer: "cus_test_#{System.unique_integer([:positive])}",
      status: "active",
      current_period_start: DateTime.to_unix(DateTime.utc_now()),
      current_period_end: DateTime.to_unix(DateTime.add(DateTime.utc_now(), 30, :day)),
      cancel_at_period_end: false,
      items: %{
        object: "list",
        data: [
          %{
            id: "si_test_#{System.unique_integer([:positive])}",
            price: %{
              id: "price_test_pro",
              unit_amount: 2900,
              currency: "usd"
            },
            quantity: 1
          }
        ]
      }
    })
  end

  @doc """
  Generate a billing event fixture for webhook testing.
  """
  def billing_event_fixture(type, attrs \\ %{}) do
    base_event = %{
      id: "evt_test_#{System.unique_integer([:positive])}",
      object: "event",
      type: type,
      created: DateTime.to_unix(DateTime.utc_now()),
      livemode: false,
      api_version: "2023-10-16"
    }

    data =
      case type do
        "customer.subscription.created" ->
          %{object: subscription_fixture(attrs)}

        "customer.subscription.updated" ->
          %{object: subscription_fixture(attrs)}

        "customer.subscription.deleted" ->
          %{object: subscription_fixture(Map.put(attrs, :status, "canceled"))}

        "invoice.payment_succeeded" ->
          %{object: invoice_fixture(attrs)}

        "invoice.payment_failed" ->
          %{object: invoice_fixture(Map.put(attrs, :status, "open"))}

        _ ->
          %{object: attrs}
      end

    Map.put(base_event, :data, data)
  end

  @doc """
  Generate a credit transaction fixture.
  """
  def credit_transaction_fixture(attrs \\ %{}) do
    Enum.into(attrs, %{
      id: System.unique_integer([:positive]),
      customer_id: nil,
      amount: 5,
      transaction_type: "signup_bonus",
      description: "Signup bonus credits",
      inserted_at: DateTime.utc_now(),
      updated_at: DateTime.utc_now()
    })
  end

  # Private helpers

  defp invoice_fixture(attrs) do
    Enum.into(attrs, %{
      id: "in_test_#{System.unique_integer([:positive])}",
      object: "invoice",
      customer: "cus_test_#{System.unique_integer([:positive])}",
      status: "paid",
      amount_paid: 2900,
      currency: "usd",
      created: DateTime.to_unix(DateTime.utc_now())
    })
  end
end
