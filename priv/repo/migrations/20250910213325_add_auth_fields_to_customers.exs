defmodule Rsolv.Repo.Migrations.AddAuthFieldsToCustomers do
  use Ecto.Migration

  def up do
    alter table(:customers) do
      # Password hash for authentication (using Argon2)
      # Use add_if_not_exists because these columns may already exist in production
      add_if_not_exists :password_hash, :string

      # Staff/admin fields
      add_if_not_exists :is_staff, :boolean, default: false, null: false
      add_if_not_exists :admin_level, :string  # Can be: nil, "read_only", "limited", "full"

      # Email should be unique for authentication
      # (This might already exist, but adding if not)
      modify :email, :string, null: false
    end

    # Ensure email is unique for authentication
    create_if_not_exists unique_index(:customers, [:email])

    # Index for finding staff members
    create_if_not_exists index(:customers, [:is_staff])
  end

  def down do
    # Drop the staff index
    drop index(:customers, [:is_staff])

    # Don't drop the unique email index - it was created by the original
    # 20240525000001_create_customers migration, not by this one.
    # We used create_if_not_exists so it already existed.

    # Remove the added columns
    alter table(:customers) do
      remove :admin_level
      remove :is_staff
      remove :password_hash

      # Note: We don't reverse the email modification as it may have been
      # nullable before, but we can't safely determine that
    end
  end
end