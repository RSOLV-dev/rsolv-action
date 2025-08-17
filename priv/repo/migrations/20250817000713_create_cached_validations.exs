defmodule Rsolv.Repo.Migrations.CreateCachedValidations do
  use Ecto.Migration

  def change do
    create table(:cached_validations) do
      add :cache_key, :text, null: false
      add :forge_account_id, references(:forge_accounts, on_delete: :delete_all), null: false
      add :repository, :string, null: false
      add :vulnerability_type, :string, null: false
      add :locations, :jsonb, null: false
      add :file_hashes, :jsonb, null: false
      
      # Validation result
      add :is_false_positive, :boolean, null: false
      add :confidence, :decimal, null: false
      add :reason, :text
      add :full_result, :jsonb
      
      # Metadata
      add :cached_at, :utc_datetime_usec, null: false
      add :ttl_expires_at, :utc_datetime_usec, null: false
      add :invalidated_at, :utc_datetime_usec
      add :invalidation_reason, :string
      
      timestamps(type: :utc_datetime_usec)
    end
    
    # Unique constraint on cache key
    create unique_index(:cached_validations, [:cache_key])
    
    # Performance indexes
    create index(:cached_validations, [:forge_account_id])
    create index(:cached_validations, [:repository])
    create index(:cached_validations, [:ttl_expires_at])
    
    # Composite index for common queries
    create index(:cached_validations, [:forge_account_id, :repository])
  end
end