defmodule Rsolv.Repo.Migrations.ConsolidateCustomerSchema do
  use Ecto.Migration

  def up do
    # Add billing fields to customers table
    alter table(:customers) do
      add_if_not_exists :trial_fixes_used, :integer, default: 0
      add_if_not_exists :trial_fixes_limit, :integer, default: 5
      add_if_not_exists :stripe_customer_id, :string
      add_if_not_exists :subscription_plan, :string, default: "trial"
      add_if_not_exists :subscription_status, :string, default: "active"
      add_if_not_exists :rollover_fixes, :integer, default: 0
      add_if_not_exists :payment_method_added_at, :utc_datetime
      add_if_not_exists :trial_expired_at, :utc_datetime
      add_if_not_exists :fixes_used_this_month, :integer, default: 0
      add_if_not_exists :fixes_quota_this_month, :integer, default: 0
      add_if_not_exists :has_payment_method, :boolean, default: false
    end
    
    # Create indices for billing fields
    create_if_not_exists index(:customers, [:stripe_customer_id])
    create_if_not_exists index(:customers, [:subscription_status])
    
    # Note: Dropping columns is handled separately after data migration
    # The following columns will be dropped in a future migration after
    # ensuring all data has been migrated:
    # - api_key (moved to api_keys table)
    # - github_org (moved to forge_accounts table)
    # - plan (renamed to subscription_plan)
    # - payment_method_added (renamed to payment_method_added_at)
    # - trial_expired (replaced by trial_expired_at)
    # - monthly_fix_quota (replaced by fixes_quota_this_month)
  end

  def down do
    # Only remove columns that this migration actually added (not ones that already existed)
    # The following columns already existed from 20250602000002_add_trial_tracking_to_customers:
    # - trial_fixes_used, trial_fixes_limit, stripe_customer_id, subscription_plan
    # - subscription_status, rollover_fixes, payment_method_added_at, trial_expired_at
    # So we only remove the NEW columns this migration added:
    alter table(:customers) do
      remove_if_exists :fixes_used_this_month, :integer
      remove_if_exists :fixes_quota_this_month, :integer
      remove_if_exists :has_payment_method, :boolean
    end

    # Don't drop indexes - they were created by the earlier migration 20250602000002
    # and will be dropped by that migration's rollback
  end
end