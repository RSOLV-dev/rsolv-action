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
end
