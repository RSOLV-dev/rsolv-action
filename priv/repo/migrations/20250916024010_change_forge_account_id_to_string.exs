defmodule Rsolv.Repo.Migrations.ChangeForgeAccountIdToString do
  use Ecto.Migration

  def change do
    # Drop the foreign key constraint and indexes
    drop index(:cached_validations, [:forge_account_id])
    drop index(:cached_validations, [:forge_account_id, :repository])
    drop constraint(:cached_validations, "cached_validations_forge_account_id_fkey")

    # Change the column type to string
    alter table(:cached_validations) do
      modify :forge_account_id, :string, null: false
    end

    # Recreate indexes with the string column
    create index(:cached_validations, [:forge_account_id])
    create index(:cached_validations, [:forge_account_id, :repository])
  end
end