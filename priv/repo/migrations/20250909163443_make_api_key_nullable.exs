defmodule Rsolv.Repo.Migrations.MakeApiKeyNullable do
  use Ecto.Migration

  def up do
    # Make api_key nullable since we're migrating to api_keys table
    # Only modify if the column exists (some environments never had this column)
    if column_exists?(:customers, :api_key) do
      alter table(:customers) do
        modify :api_key, :string, null: true
      end
    end
  end

  def down do
    # Revert api_key back to NOT NULL
    # Only modify if the column exists
    if column_exists?(:customers, :api_key) do
      alter table(:customers) do
        modify :api_key, :string, null: false
      end
    end
  end

  defp column_exists?(table, column) do
    query = """
    SELECT EXISTS (
      SELECT 1
      FROM information_schema.columns
      WHERE table_name = '#{table}'
      AND column_name = '#{column}'
    )
    """
    {:ok, %{rows: [[exists]]}} = Ecto.Adapters.SQL.query(Rsolv.Repo, query)
    exists
  end
end