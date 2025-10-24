defmodule Rsolv.Repo.Migrations.AddKeyHashToApiKeys do
  use Ecto.Migration

  @moduledoc """
  Migration to add SHA256 hashing for API keys.

  This migration follows a safe multi-phase approach:
  1. Add key_hash column (nullable)
  2. Backfill existing keys with their SHA256 hashes
  3. Make key_hash non-nullable and add index
  4. Drop the old plaintext key column

  See RFC-065 for full specification.
  """

  def up do
    # Enable pgcrypto extension for digest function
    execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    # Phase 1: Add key_hash column (nullable initially)
    alter table(:api_keys) do
      add :key_hash, :string, size: 64
    end

    # Phase 2: Backfill existing keys with their SHA256 hashes
    # This runs within the same migration to ensure consistency
    flush()

    execute("""
    UPDATE api_keys
    SET key_hash = encode(digest(key, 'sha256'), 'hex')
    WHERE key IS NOT NULL
    """)

    # Phase 3: Make key_hash non-nullable and add unique index
    flush()

    alter table(:api_keys) do
      modify :key_hash, :string, null: false, size: 64
    end

    create unique_index(:api_keys, [:key_hash])

    # Phase 4: Drop old key column
    alter table(:api_keys) do
      remove :key
    end
  end

  def down do
    # Add back the key column
    alter table(:api_keys) do
      add :key, :string
    end

    # Drop the unique index
    drop unique_index(:api_keys, [:key_hash])

    # Remove key_hash column
    alter table(:api_keys) do
      remove :key_hash
    end

    # Note: We cannot restore the original plaintext keys as they were hashed
    # This is intentional - the migration is partially irreversible for security
    execute("UPDATE api_keys SET key = 'ROLLBACK_' || id::text || '_REGENERATE_REQUIRED'")

    # Drop pgcrypto extension (only if safe to do so)
    execute("DROP EXTENSION IF EXISTS pgcrypto")
  end
end
