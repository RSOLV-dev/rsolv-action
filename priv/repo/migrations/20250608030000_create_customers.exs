defmodule RsolvApi.Repo.Migrations.CreateCustomers do
  use Ecto.Migration

  def change do
    create table(:customers) do
      add :name, :string, null: false
      add :email, :string
      add :api_key, :string, null: false
      add :tier, :string, null: false, default: "teams"
      add :ai_enabled, :boolean, default: false
      add :is_active, :boolean, default: true
      add :metadata, :map, default: %{}

      timestamps()
    end

    create unique_index(:customers, [:api_key])
    create unique_index(:customers, [:email])
    create index(:customers, [:is_active])
    create index(:customers, [:tier])
  end
end