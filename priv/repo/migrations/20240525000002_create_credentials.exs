defmodule Rsolv.Repo.Migrations.CreateCredentials do
  use Ecto.Migration

  def change do
    create table(:credentials) do
      add :customer_id, references(:customers, on_delete: :delete_all), null: false
      add :provider, :string, null: false
      add :encrypted_key, :text, null: false
      add :expires_at, :utc_datetime, null: false
      add :usage_limit, :integer
      add :usage_count, :integer, default: 0
      add :metadata, :map, default: %{}
      add :revoked, :boolean, default: false

      timestamps()
    end

    create index(:credentials, [:customer_id])
    create index(:credentials, [:provider])
    create index(:credentials, [:expires_at])
    create index(:credentials, [:revoked])
  end
end