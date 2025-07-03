defmodule RsolvLanding.Repo.Migrations.CreateFunWithFlagsTables do
  use Ecto.Migration

  def up do
    create table(:fun_with_flags_toggles, primary_key: false) do
      add :id, :bigserial, primary_key: true
      add :flag_name, :string, null: false
      add :gate_type, :string, null: false
      add :target, :string
      add :enabled, :boolean, null: false
    end

    create unique_index(:fun_with_flags_toggles, [:flag_name, :gate_type, :target])
    
    # Seed initial feature flags based on our current needs
    execute """
    INSERT INTO fun_with_flags_toggles (flag_name, gate_type, target, enabled) VALUES
    -- Dashboard features - disabled by default
    ('admin_dashboard', 'boolean', NULL, false),
    ('metrics_dashboard', 'boolean', NULL, false),
    ('feedback_dashboard', 'boolean', NULL, false),
    
    -- Landing page features - enabled by default
    ('interactive_roi_calculator', 'boolean', NULL, true),
    ('team_size_field', 'boolean', NULL, true),
    ('feedback_form', 'boolean', NULL, true),
    
    -- Early access features - enabled by default
    ('early_access_signup', 'boolean', NULL, true),
    ('welcome_email_sequence', 'boolean', NULL, true),
    
    -- Premium features - disabled by default
    ('advanced_analytics', 'boolean', NULL, false),
    ('custom_templates', 'boolean', NULL, false),
    ('team_collaboration', 'boolean', NULL, false),
    ('api_access', 'boolean', NULL, false),
    ('priority_support', 'boolean', NULL, false)
    ON CONFLICT DO NOTHING;
    """
  end

  def down do
    drop table(:fun_with_flags_toggles)
  end
end