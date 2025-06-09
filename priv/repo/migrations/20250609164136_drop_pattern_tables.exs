defmodule RsolvApi.Repo.Migrations.DropPatternTables do
  use Ecto.Migration

  def change do
    # Drop security_patterns table first (has foreign key to pattern_tiers)
    drop table(:security_patterns)
    
    # Drop pattern_tiers table
    drop table(:pattern_tiers)
  end
end