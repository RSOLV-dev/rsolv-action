defmodule Rsolv.Billing.StripeClientBehaviour do
  @moduledoc """
  Behaviour defining the Stripe client interface for mocking in tests.

  This behaviour covers all Stripe API operations needed for the billing system:
  - Customer creation and management
  - Payment method attachment
  - Subscription lifecycle (create, update, cancel)
  - Invoice retrieval
  - Charge creation (for PAYG and Pro additional fixes)

  Implementations: `Rsolv.Billing.StripeService` (production),
                   `Rsolv.Billing.StripeTestStub` (test stub)
  """

  # Wrapped methods (used by StripeService high-level functions)
  @callback create_customer(map()) :: {:ok, map()} | {:error, term()}
  @callback retrieve_customer(String.t()) :: {:ok, map()} | {:error, term()}
  @callback update_customer(String.t(), map()) :: {:ok, map()} | {:error, term()}
  @callback attach_payment_method(String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  @callback create_subscription(map()) :: {:ok, map()} | {:error, term()}
  @callback update_subscription(String.t(), map()) :: {:ok, map()} | {:error, term()}
  @callback cancel_subscription(String.t()) :: {:ok, map()} | {:error, term()}
  @callback retrieve_invoice(String.t()) :: {:ok, map()} | {:error, term()}
  @callback create_charge(map()) :: {:ok, map()} | {:error, term()}

  # Raw Stripe API methods (called directly by StripeService via module attributes)
  # These match the actual Stripe library API:
  # - Stripe.Customer.create/1, retrieve/1, update/2
  # - Stripe.PaymentMethod.attach/1
  # - Stripe.Subscription.create/1, update/2, cancel/1
  @callback create(map()) :: {:ok, map()} | {:error, term()}
  @callback retrieve(String.t()) :: {:ok, map()} | {:error, term()}
  @callback update(String.t(), map()) :: {:ok, map()} | {:error, term()}
  @callback attach(map()) :: {:ok, map()} | {:error, term()}
  @callback cancel(String.t()) :: {:ok, map()} | {:error, term()}
end

defmodule Rsolv.Billing.StripeChargeBehaviour do
  @moduledoc """
  Behaviour for Stripe.Charge operations.
  Separate from StripeClientBehaviour to match Stripe module structure.
  """

  # Stripe.Charge methods
  @callback create(map()) :: {:ok, map()} | {:error, Stripe.Error.t()}
end
