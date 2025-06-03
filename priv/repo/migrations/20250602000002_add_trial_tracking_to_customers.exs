defmodule RSOLV.Repo.Migrations.AddTrialTrackingToCustomers do
  use Ecto.Migration

  def change do
    alter table(:customers) do
      # Trial tracking
      add :trial_fixes_used, :integer, default: 0
      add :trial_fixes_limit, :integer, default: 10
      add :trial_expired, :boolean, default: false
      add :trial_expired_at, :utc_datetime_usec
      
      # Payment status
      add :payment_method_added, :boolean, default: false
      add :payment_method_added_at, :utc_datetime_usec
      add :stripe_customer_id, :string
      
      # Plan tracking
      add :subscription_plan, :string, default: "pay_as_you_go" # pay_as_you_go, teams, enterprise
      add :subscription_status, :string, default: "trial" # trial, active, past_due, cancelled
      add :monthly_fix_quota, :integer
      add :rollover_fixes, :integer, default: 0
    end
    
    create index(:customers, [:trial_expired])
    create index(:customers, [:subscription_status])
    create index(:customers, [:stripe_customer_id])
  end
end