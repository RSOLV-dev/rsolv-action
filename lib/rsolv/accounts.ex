defmodule Rsolv.Accounts do
  @moduledoc """
  The Accounts context.

  This module serves as a compatibility layer, delegating to the new Customers context.
  All User-based functionality has been removed as part of RFC-049.
  """

  # Compatibility functions - delegate to the new contexts
  defdelegate get_customer_by_api_key(api_key), to: Rsolv.Customers
  defdelegate get_customer!(id), to: Rsolv.Customers
  defdelegate update_customer(customer, attrs), to: Rsolv.Customers
  defdelegate record_usage(usage_attrs), to: Rsolv.Billing
end
