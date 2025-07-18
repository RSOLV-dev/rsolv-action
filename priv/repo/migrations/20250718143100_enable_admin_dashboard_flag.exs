defmodule Rsolv.Repo.Migrations.EnableAdminDashboardFlag do
  use Ecto.Migration

  def up do
    # Enable admin_dashboard feature flag globally
    execute """
    INSERT INTO fun_with_flags_toggles (flag_name, gate_type, enabled, inserted_at, updated_at)
    VALUES ('admin_dashboard', 'boolean', true, NOW(), NOW())
    ON CONFLICT (flag_name, gate_type) 
    DO UPDATE SET enabled = true, updated_at = NOW();
    """
  end

  def down do
    execute """
    DELETE FROM fun_with_flags_toggles 
    WHERE flag_name = 'admin_dashboard' AND gate_type = 'boolean';
    """
  end
end