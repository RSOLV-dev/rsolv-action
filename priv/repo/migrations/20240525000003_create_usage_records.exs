defmodule Rsolv.Repo.Migrations.CreateUsageRecords do
  use Ecto.Migration

  def change do
    create table(:usage_records) do
      add :customer_id, references(:customers, on_delete: :delete_all), null: false
      add :credential_id, references(:credentials, on_delete: :nilify_all)
      add :provider, :string, null: false
      add :tokens_used, :integer, default: 0
      add :request_count, :integer, default: 0
      add :job_id, :string
      add :github_run_id, :string
      add :metadata, :map, default: %{}

      timestamps()
    end

    create index(:usage_records, [:customer_id])
    create index(:usage_records, [:credential_id])
    create index(:usage_records, [:provider])
    create index(:usage_records, [:job_id])
    create index(:usage_records, :inserted_at)
  end
end