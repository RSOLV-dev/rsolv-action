defmodule Rsolv.Repo.Migrations.RemoveUserDependencyFromCustomers do
  use Ecto.Migration

  def up do
    # Drop the index first
    drop index(:customers, [:user_id])

    # Remove the user_id column
    alter table(:customers) do
      remove :user_id
    end
  end

  def down do
    # Re-add the user_id column with foreign key reference
    alter table(:customers) do
      add :user_id, references(:users, on_delete: :restrict)
    end

    # Recreate the index
    create index(:customers, [:user_id])
  end
end