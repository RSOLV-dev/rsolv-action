defmodule Rsolv.Repo.Migrations.DropPatternTables do
  use Ecto.Migration

  def up do
    # Drop security_patterns table first (has foreign key to pattern_tiers)
    drop table(:security_patterns)

    # Drop pattern_tiers table
    drop table(:pattern_tiers)
  end

  def down do
    # Recreate pattern_tiers table
    # This matches the structure from 20250607235726_create_security_patterns.exs
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

    # Recreate security_patterns table
    create table(:security_patterns) do
      add :name, :string, null: false
      add :description, :text, null: false
      add :language, :string, null: false
      add :type, :string, null: false
      add :severity, :string, null: false
      add :cwe_id, :string
      add :owasp_category, :string
      add :remediation, :text
      add :confidence, :string, default: "medium"
      add :framework, :string

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

    # Reinsert default tiers
    execute """
    INSERT INTO pattern_tiers (name, description, auth_required, api_key_required, enterprise_required, ai_flag_required, display_order, inserted_at, updated_at) VALUES
    ('public', 'Public patterns for trust building and demos', false, false, false, false, 1, NOW(), NOW()),
    ('protected', 'Advanced patterns requiring API authentication', true, true, false, false, 2, NOW(), NOW()),
    ('ai', 'AI-specific vulnerability detection patterns', true, true, false, true, 3, NOW(), NOW()),
    ('enterprise', 'Custom enterprise patterns', true, true, true, false, 4, NOW(), NOW());
    """
  end
end