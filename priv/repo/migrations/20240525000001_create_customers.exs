defmodule Rsolv.Repo.Migrations.CreateCustomers do
  use Ecto.Migration

  def change do
    create table(:customers) do
      add :name, :string, null: false
      add :email, :string, null: false
      add :api_key, :string, null: false
      add :monthly_limit, :integer, default: 100
      add :current_usage, :integer, default: 0
      add :active, :boolean, default: true
      add :metadata, :map, default: %{}

      timestamps()
    end

    create unique_index(:customers, [:email])
    create unique_index(:customers, [:api_key])
    create index(:customers, [:active])
  end
end