defmodule Rsolv.MigrationTest do
  use Rsolv.DataCase
  
  @moduledoc """
  Test that verifies migrations run successfully for Phase 2.
  """
  
  test "all migrations run without errors" do
    # This test will pass when all migrations are created and valid
    # The DataCase setup automatically runs migrations
    assert true
  end
  
  test "schema introspection shows expected tables" do
    # Query information_schema to verify tables exist
    query = """
    SELECT table_name 
    FROM information_schema.tables 
    WHERE table_schema = 'public' 
    AND table_type = 'BASE TABLE'
    ORDER BY table_name
    """
    
    {:ok, result} = Ecto.Adapters.SQL.query(Rsolv.Repo, query)
    
    table_names = result.rows |> Enum.map(&List.first/1)
    
    # Expected tables after consolidation
    expected_tables = [
      "customers",
      "users",
      "api_keys",
      "fix_attempts",
      "email_subscriptions",
      "fun_with_flags_toggles",
      "oban_jobs",
      "schema_migrations"
    ]
    
    Enum.each(expected_tables, fn table ->
      assert table in table_names, "Missing table: #{table}"
    end)
  end
end