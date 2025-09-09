defmodule Rsolv.Repo.Migrations.MakeApiKeyNullable do
  use Ecto.Migration

  def up do
    # Make api_key nullable since we're migrating to api_keys table
    alter table(:customers) do
      modify :api_key, :string, null: true
    end
  end

  def down do
    # Revert api_key back to NOT NULL
    alter table(:customers) do
      modify :api_key, :string, null: false
    end
  end
end