defmodule Rsolv.Repo.Migrations.AddPublicSiteFeatureFlag do
  use Ecto.Migration

  def up do
    # Add public_site feature flag for RFC-078
    # This flag controls the visibility of the public site (landing, pricing, signup pages)
    # Deployed to production with flag OFF, enabling safe staging testing before go-live
    execute """
    INSERT INTO fun_with_flags_toggles (flag_name, gate_type, target, enabled) VALUES
    ('public_site', 'boolean', NULL, false)
    ON CONFLICT (flag_name, gate_type, target)
    DO UPDATE SET enabled = false;
    """
  end

  def down do
    # Remove public_site feature flag
    execute """
    DELETE FROM fun_with_flags_toggles WHERE flag_name = 'public_site';
    """
  end
end
