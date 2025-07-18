defmodule Rsolv.Repo.Migrations.EnableMetricsDashboardFlag do
  use Ecto.Migration

  def up do
    # Enable metrics_dashboard feature flag globally
    execute """
    UPDATE fun_with_flags_toggles 
    SET enabled = true
    WHERE flag_name = 'metrics_dashboard' AND gate_type = 'boolean';
    """
  end

  def down do
    execute """
    DELETE FROM fun_with_flags_toggles 
    WHERE flag_name = 'metrics_dashboard' AND gate_type = 'boolean';
    """
  end
end