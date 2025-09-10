defmodule Rsolv.Repo.Migrations.AddAuthFieldsToCustomers do
  use Ecto.Migration

  def change do
    alter table(:customers) do
      # Password hash for authentication (using Argon2)
      add :password_hash, :string
      
      # Staff/admin fields
      add :is_staff, :boolean, default: false, null: false
      add :admin_level, :string  # Can be: nil, "read_only", "limited", "full"
      
      # Email should be unique for authentication
      # (This might already exist, but adding if not)
      modify :email, :string, null: false
    end
    
    # Ensure email is unique for authentication
    create_if_not_exists unique_index(:customers, [:email])
    
    # Index for finding staff members
    create index(:customers, [:is_staff])
  end
end