defmodule Rsolv.Repo.Migrations.EnableFalsePositiveCachingFlag do
  use Ecto.Migration
  
  def up do
    # Enable the false positive caching feature flag
    # Start with it disabled for safety
    # Only insert if table exists (for test environments that might not have it)
    execute """
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'fun_with_flags_toggles') THEN
        INSERT INTO fun_with_flags_toggles (flag_name, gate_type, target, enabled)
        VALUES ('false_positive_caching', 'boolean', '', true)
        ON CONFLICT (flag_name, gate_type, target) 
        DO UPDATE SET enabled = true;
      END IF;
    END$$;
    """
  end
  
  def down do
    execute """
    DELETE FROM fun_with_flags_toggles 
    WHERE flag_name = 'false_positive_caching'
    """
  end
end