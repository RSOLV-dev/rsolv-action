defmodule Rsolv.Repo.Migrations.RemoveUserDependencyFromCustomers do
  use Ecto.Migration

  def change do
    alter table(:customers) do
      remove :user_id
    end
  end
end