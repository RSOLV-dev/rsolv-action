defmodule Rsolv.Repo.Migrations.CreateSecurityPatterns do
  use Ecto.Migration

  def change do
    # Create pattern tiers table for access control
    create table(:pattern_tiers) do
      add :name, :string, null: false
      add :description, :string
      add :auth_required, :boolean, default: false
      add :api_key_required, :boolean, default: false
      add :enterprise_required, :boolean, default: false
      add :ai_flag_required, :boolean, default: false
      add :display_order, :integer, default: 0

      timestamps()
    end

    create unique_index(:pattern_tiers, [:name])

    # Create security patterns table
    create table(:security_patterns) do
      add :name, :string, null: false
      add :description, :text, null: false
      add :language, :string, null: false
      add :type, :string, null: false # vulnerability type
      add :severity, :string, null: false # low, medium, high, critical
      add :cwe_id, :string
      add :owasp_category, :string
      add :remediation, :text
      add :confidence, :string, default: "medium"
      add :framework, :string # rails, django, express, etc.
      
      # Pattern matching data
      add :regex_patterns, {:array, :string}, default: []
      add :safe_usage_patterns, {:array, :string}, default: []
      add :example_code, :text
      add :fix_template, :text
      
      # Tier assignment
      add :tier_id, references(:pattern_tiers, on_delete: :restrict), null: false
      
      # Metadata
      add :is_active, :boolean, default: true
      add :source, :string, default: "rsolv"
      add :tags, {:array, :string}, default: []

      timestamps()
    end

    create index(:security_patterns, [:language])
    create index(:security_patterns, [:type])
    create index(:security_patterns, [:severity])
    create index(:security_patterns, [:tier_id])
    create index(:security_patterns, [:is_active])
    create index(:security_patterns, [:language, :tier_id])
    create unique_index(:security_patterns, [:name, :language, :type])

    # Insert default tiers
    execute """
    INSERT INTO pattern_tiers (name, description, auth_required, api_key_required, enterprise_required, ai_flag_required, display_order, inserted_at, updated_at) VALUES
    ('public', 'Public patterns for trust building and demos', false, false, false, false, 1, NOW(), NOW()),
    ('protected', 'Advanced patterns requiring API authentication', true, true, false, false, 2, NOW(), NOW()),
    ('ai', 'AI-specific vulnerability detection patterns', true, true, false, true, 3, NOW(), NOW()),
    ('enterprise', 'Custom enterprise patterns', true, true, true, false, 4, NOW(), NOW());
    """
  end
end
