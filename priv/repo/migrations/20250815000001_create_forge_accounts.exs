defmodule Rsolv.Repo.Migrations.CreateForgeAccounts do
  use Ecto.Migration

  def change do
    # Create enum for forge types (GitHub now, GitLab later)
    execute """
      CREATE TYPE forge_type AS ENUM ('github')
    """, """
      DROP TYPE forge_type
    """

    create table(:forge_accounts) do
      add :customer_id, references(:customers, on_delete: :delete_all), null: false
      add :forge_type, :forge_type, null: false
      add :namespace, :string, null: false  # e.g., "RSOLV-dev" 
      add :verified_at, :utc_datetime_usec
      add :metadata, :jsonb, default: "{}"
      
      timestamps(type: :utc_datetime_usec)
    end

    # Ensure unique namespace per forge type per customer
    create unique_index(:forge_accounts, [:customer_id, :forge_type, :namespace])
    create index(:forge_accounts, [:forge_type, :namespace])
    create index(:forge_accounts, [:customer_id])
  end
end