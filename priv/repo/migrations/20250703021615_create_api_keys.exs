defmodule Rsolv.Repo.Migrations.CreateApiKeys do
  use Ecto.Migration

  def change do
    create table(:api_keys) do
      add :key, :string, null: false
      add :name, :string
      add :customer_id, references(:customers, on_delete: :delete_all), null: false
      add :permissions, {:array, :string}, default: []
      add :last_used_at, :naive_datetime
      add :expires_at, :naive_datetime
      add :active, :boolean, default: true
      
      timestamps(type: :utc_datetime)
    end

    create unique_index(:api_keys, [:key])
    create index(:api_keys, [:customer_id])
    create index(:api_keys, [:active])
  end
end