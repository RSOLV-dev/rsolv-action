defmodule Rsolv.Repo.Migrations.AddCustomerOnboardingFields do
  use Ecto.Migration

  def up do
    # Add provisioning tracking fields to customers
    alter table(:customers) do
      add :auto_provisioned, :boolean, default: false
      add :wizard_preference, :string, default: "auto"  # auto/hidden/shown
      add :first_scan_at, :utc_datetime
    end

    # Create customer onboarding events table for audit trail
    create table(:customer_onboarding_events, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :customer_id, references(:customers, on_delete: :delete_all)
      add :event_type, :string, null: false  # "customer_created", "api_key_generated", etc.
      add :status, :string, null: false      # "success", "failed", "retrying"
      add :metadata, :map                    # JSONB for additional context

      timestamps(type: :utc_datetime)
    end

    create index(:customer_onboarding_events, [:customer_id])
    create index(:customer_onboarding_events, [:event_type])
    create index(:customer_onboarding_events, [:inserted_at])
  end

  def down do
    drop table(:customer_onboarding_events)

    alter table(:customers) do
      remove :auto_provisioned
      remove :wizard_preference
      remove :first_scan_at
    end
  end
end
