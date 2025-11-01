defmodule Rsolv.Repo.Migrations.AddCreditBalanceCheckConstraint do
  use Ecto.Migration

  @moduledoc """
  RFC-069 Wednesday: Add check constraint to prevent negative credit balances.

  ## Background

  Error handling tests uncovered a critical race condition in credit_ledger.ex:
  - Multiple concurrent consume() calls could all pass the `new_balance < 0` check
  - This happened because the check occurred OUTSIDE the database transaction
  - Result: Customers could overdraw credits under concurrent load

  ## Solution

  Database check constraint enforces `credit_balance >= 0` at UPDATE time:
  - Constraint violation caught during transaction
  - Application layer handles gracefully (returns :insufficient_credits)
  - No possibility of negative balance, even under high concurrency

  ## Testing

  Verified by test: test/rsolv/billing/error_handling_and_recovery_test.exs:151-183
  - Concurrent credit consumption prevented from going negative
  - Test passes after constraint added

  ## Rollback

  Constraint can be safely dropped - application-level check still exists
  """

  def up do
    # Add check constraint to prevent negative credit balances
    # This is enforced at the database level during UPDATE operations
    execute """
    ALTER TABLE customers
    ADD CONSTRAINT credit_balance_non_negative
    CHECK (credit_balance >= 0)
    """
  end

  def down do
    # Remove check constraint
    # Application-level check in credit_ledger.ex still prevents negatives
    # but race condition vulnerability returns
    execute """
    ALTER TABLE customers
    DROP CONSTRAINT credit_balance_non_negative
    """
  end
end
