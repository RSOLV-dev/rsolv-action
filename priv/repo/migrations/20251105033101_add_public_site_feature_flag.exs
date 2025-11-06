defmodule Rsolv.Repo.Migrations.AddPublicSiteFeatureFlag do
  use Ecto.Migration

  def up do
    # Add public_site feature flag for RFC-078
    # This flag controls the visibility of the public site (landing, pricing, signup pages)
    # Deployed to production with flag OFF, enabling safe staging testing before go-live
    #
    # Note: FunWithFlags will create the actual toggle record when enable/disable is first called.
    # We don't pre-create it here to avoid conflicts with FunWithFlags' internal target management.
    # The flag will default to disabled (false) until explicitly enabled.
    :ok
  end

  def down do
    # Remove public_site feature flag
    execute """
    DELETE FROM fun_with_flags_toggles WHERE flag_name = 'public_site';
    """
  end
end
