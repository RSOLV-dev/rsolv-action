defmodule Rsolv.Repo.Migrations.EnablePublicSiteFlag do
  use Ecto.Migration

  def up do
    # Create public_site feature flag (disabled by default)
    # This flag gates all RFC-078 public site pages: landing, pricing, signup
    execute """
    INSERT INTO fun_with_flags_toggles (flag_name, gate_type, target, enabled)
    VALUES ('public_site', 'boolean', NULL, false)
    ON CONFLICT DO NOTHING;
    """
  end

  def down do
    # Remove the public_site flag
    execute """
    DELETE FROM fun_with_flags_toggles
    WHERE flag_name = 'public_site' AND gate_type = 'boolean';
    """
  end
end
