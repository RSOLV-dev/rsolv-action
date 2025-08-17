defmodule Rsolv.Repo.Migrations.EnableFalsePositiveCachingFlag do
  use Ecto.Migration
  
  def up do
    # Enable the false positive caching feature flag
    # Start with it disabled for safety
    execute """
    INSERT INTO fun_with_flags_toggles (flag_name, gate_type, target, enabled, inserted_at, updated_at)
    VALUES ('false_positive_caching', 'boolean', '', false, NOW(), NOW())
    ON CONFLICT (flag_name, gate_type, target) 
    DO UPDATE SET enabled = false, updated_at = NOW()
    """
  end
  
  def down do
    execute """
    DELETE FROM fun_with_flags_toggles 
    WHERE flag_name = 'false_positive_caching'
    """
  end
end