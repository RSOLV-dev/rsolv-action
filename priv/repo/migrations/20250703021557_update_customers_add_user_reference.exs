defmodule Rsolv.Repo.Migrations.UpdateCustomersAddUserReference do
  use Ecto.Migration

  def change do
    alter table(:customers) do
      add :user_id, references(:users, on_delete: :restrict)
      add :github_org, :string
      add :plan, :string, default: "trial"
    end

    create index(:customers, [:user_id])
  end
end