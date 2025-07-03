defmodule Rsolv.Repo.Migrations.CreateFixAttempts do
  use Ecto.Migration

  def change do
    create table(:fix_attempts) do
      # GitHub/Platform identifiers
      add :github_org, :string, null: false
      add :repo_name, :string, null: false
      add :issue_number, :integer, null: false
      add :pr_number, :integer
      add :platform, :string, default: "github"
      
      # Customer tracking
      add :customer_id, references(:customers, on_delete: :restrict)
      add :api_key_used, :string
      
      # Status tracking
      add :status, :string, default: "pending" # pending, merged, rejected, timeout
      add :billing_status, :string, default: "not_billed" # not_billed, billed, refunded, disputed
      
      # Timing
      add :created_at, :utc_datetime_usec
      add :merged_at, :utc_datetime_usec
      add :billed_at, :utc_datetime_usec
      add :refunded_at, :utc_datetime_usec
      
      # Financial
      add :amount, :decimal, precision: 10, scale: 2
      add :currency, :string, default: "USD"
      
      # Metadata
      add :pr_title, :text
      add :pr_url, :string
      add :issue_title, :text
      add :issue_url, :string
      add :commit_sha, :string
      add :merged_by, :string
      add :metadata, :map, default: %{}
      
      # Manual approval
      add :requires_manual_approval, :boolean, default: true
      add :approved_by, :string
      add :approved_at, :utc_datetime_usec
      add :approval_notes, :text
      
      timestamps()
    end

    # Indexes for fast lookups
    create unique_index(:fix_attempts, [:github_org, :repo_name, :pr_number])
    create index(:fix_attempts, [:customer_id])
    create index(:fix_attempts, [:status])
    create index(:fix_attempts, [:billing_status])
    create index(:fix_attempts, [:created_at])
    create index(:fix_attempts, [:merged_at])
    create index(:fix_attempts, [:api_key_used])
  end
end