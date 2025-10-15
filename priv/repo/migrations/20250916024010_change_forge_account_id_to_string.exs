defmodule Rsolv.Repo.Migrations.ChangeForgeAccountIdToString do
  use Ecto.Migration

  def up do
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

  def down do
    # Drop indexes
    drop index(:cached_validations, [:forge_account_id, :repository])
    drop index(:cached_validations, [:forge_account_id])

    # Change the column type back to bigint using explicit USING clause
    execute """
    ALTER TABLE cached_validations
    ALTER COLUMN forge_account_id TYPE bigint
    USING forge_account_id::bigint
    """

    # Recreate the foreign key constraint and indexes
    create index(:cached_validations, [:forge_account_id])
    create index(:cached_validations, [:forge_account_id, :repository])

    alter table(:cached_validations) do
      modify :forge_account_id, references(:forge_accounts, on_delete: :delete_all)
    end
  end
end