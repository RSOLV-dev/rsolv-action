defmodule Rsolv.Repo.Migrations.EnableAdminDashboardFlag do
  use Ecto.Migration

  def up do
    # Enable admin_dashboard feature flag globally
    execute """
    UPDATE fun_with_flags_toggles 
    SET enabled = true
    WHERE flag_name = 'admin_dashboard' AND gate_type = 'boolean';
    """
  end

  def down do
    execute """
    DELETE FROM fun_with_flags_toggles 
    WHERE flag_name = 'admin_dashboard' AND gate_type = 'boolean';
    """
  end
end