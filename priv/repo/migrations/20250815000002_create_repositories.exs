defmodule Rsolv.Repo.Migrations.CreateRepositories do
  use Ecto.Migration

  def change do
    create table(:repositories) do
      add :forge_type, :string, null: false
      add :namespace, :string, null: false  # e.g., "RSOLV-dev"
      add :name, :string, null: false       # e.g., "nodegoat-demo"
      add :full_path, :string, null: false  # computed: "RSOLV-dev/nodegoat-demo"
      add :customer_id, references(:customers, on_delete: :nilify_all)
      add :first_seen_at, :utc_datetime_usec, null: false
      add :last_activity_at, :utc_datetime_usec, null: false
      add :metadata, :jsonb, default: "{}"
      
      timestamps(type: :utc_datetime_usec)
    end

    # Unique constraint on forge + namespace + name
    create unique_index(:repositories, [:forge_type, :namespace, :name])
    create index(:repositories, [:customer_id])
    create index(:repositories, [:last_activity_at])
    create index(:repositories, [:forge_type, :namespace])
  end
end