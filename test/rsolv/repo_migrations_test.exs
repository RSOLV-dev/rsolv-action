defmodule Rsolv.RepoMigrationsTest do
  use Rsolv.DataCase, async: false

  @moduletag :migration_test

  describe "phase data persistence tables" do
    test "all required phase data tables exist with correct structure" do
      # Migrations run automatically via mix ecto.reset
      # Verify all tables exist
      assert {:ok, _} = Repo.query("SELECT * FROM forge_accounts LIMIT 1")
      assert {:ok, _} = Repo.query("SELECT * FROM repositories LIMIT 1")
      assert {:ok, _} = Repo.query("SELECT * FROM scan_executions LIMIT 1")
      assert {:ok, _} = Repo.query("SELECT * FROM validation_executions LIMIT 1")
      assert {:ok, _} = Repo.query("SELECT * FROM mitigation_executions LIMIT 1")

      # Verify key columns exist in forge_accounts
      assert {:ok, result} =
               Repo.query(
                 "SELECT column_name FROM information_schema.columns 
                                         WHERE table_name = 'forge_accounts' 
                                         AND column_name IN ('namespace', 'forge_type', 'customer_id')"
               )

      assert length(result.rows) == 3

      # Verify key columns exist in repositories
      assert {:ok, result} = Repo.query("SELECT column_name FROM information_schema.columns 
                                         WHERE table_name = 'repositories' 
                                         AND column_name IN ('namespace', 'name', 'full_path')")
      assert length(result.rows) == 3

      # Verify foreign key relationships work
      assert {:ok, result} = Repo.query("
        SELECT 
          tc.constraint_name,
          tc.table_name,
          kcu.column_name,
          ccu.table_name AS foreign_table_name
        FROM information_schema.table_constraints AS tc 
        JOIN information_schema.key_column_usage AS kcu
          ON tc.constraint_name = kcu.constraint_name
        JOIN information_schema.constraint_column_usage AS ccu
          ON ccu.constraint_name = tc.constraint_name
        WHERE tc.constraint_type = 'FOREIGN KEY' 
          AND tc.table_name IN ('forge_accounts', 'repositories', 'scan_executions', 
                                'validation_executions', 'mitigation_executions')
      ")

      # Should have FK relationships
      assert length(result.rows) > 0

      # Verify enums were created
      assert {:ok, result} =
               Repo.query(
                 "SELECT typname FROM pg_type WHERE typname IN ('forge_type', 'execution_status')"
               )

      assert length(result.rows) == 2
    end
  end
end
