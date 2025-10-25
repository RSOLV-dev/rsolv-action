defmodule Rsolv.Repo.Migrations.CreateBillingTables do
  use Ecto.Migration

  def up do
    # Add billing fields to customers table
    alter table(:customers) do
      add :credit_balance, :integer, default: 0, null: false
      add :stripe_payment_method_id, :string
      add :stripe_subscription_id, :string
      add :billing_consent_given, :boolean, default: false, null: false
      add :billing_consent_at, :utc_datetime
      add :subscription_cancel_at_period_end, :boolean, default: false, null: false
    end

    # Rename existing subscription fields for clarity
    # subscription_plan → subscription_type (pricing tier: trial, pay_as_you_go, pro)
    # subscription_status → subscription_state (Stripe lifecycle: active, past_due, canceled, etc.)
    rename table(:customers), :subscription_plan, to: :subscription_type
    rename table(:customers), :subscription_status, to: :subscription_state

    # Drop the existing regular index on stripe_customer_id before creating unique index
    drop_if_exists index(:customers, [:stripe_customer_id])
    create unique_index(:customers, [:stripe_customer_id])

    # Credit transactions ledger
    create table(:credit_transactions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :customer_id, references(:customers, on_delete: :delete_all), null: false
      add :amount, :integer, null: false  # positive = credit, negative = debit
      add :balance_after, :integer, null: false
      add :source, :string, null: false  # trial_signup, trial_billing_added, pro_subscription_payment, purchased, consumed
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime)
    end

    create index(:credit_transactions, [:customer_id])
    create index(:credit_transactions, [:inserted_at])

    # Pro subscriptions
    create table(:subscriptions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :customer_id, references(:customers, on_delete: :delete_all), null: false
      add :stripe_subscription_id, :string, null: false
      add :plan, :string, null: false  # "pro"
      add :status, :string, null: false  # active, past_due, canceled, unpaid
      add :current_period_start, :utc_datetime
      add :current_period_end, :utc_datetime
      add :cancel_at_period_end, :boolean, default: false

      timestamps(type: :utc_datetime)
    end

    create unique_index(:subscriptions, [:stripe_subscription_id])
    create index(:subscriptions, [:customer_id])

    # Billing events (webhook idempotency + audit)
    create table(:billing_events, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :customer_id, references(:customers, on_delete: :nilify_all)
      add :stripe_event_id, :string, null: false
      add :event_type, :string, null: false
      add :amount_cents, :integer
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime)
    end

    create unique_index(:billing_events, [:stripe_event_id])  # Idempotency
    create index(:billing_events, [:customer_id])
    create index(:billing_events, [:event_type])
  end

  def down do
    drop table(:billing_events)
    drop table(:subscriptions)
    drop table(:credit_transactions)

    # Reverse the renames
    rename table(:customers), :subscription_state, to: :subscription_status
    rename table(:customers), :subscription_type, to: :subscription_plan

    # Drop the unique index and restore the regular index on stripe_customer_id
    drop_if_exists unique_index(:customers, [:stripe_customer_id])
    create index(:customers, [:stripe_customer_id])

    alter table(:customers) do
      remove :credit_balance
      remove :stripe_payment_method_id
      remove :stripe_subscription_id
      remove :billing_consent_given
      remove :billing_consent_at
      remove :subscription_cancel_at_period_end
    end
  end
end
