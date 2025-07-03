defmodule Rsolv.Repo.Migrations.CreateEarlyAccessSignups do
  use Ecto.Migration

  def change do
    create table(:early_access_signups) do
      add :email, :string, null: false
      add :name, :string
      add :company, :string
      add :referral_source, :string
      add :utm_source, :string
      add :utm_medium, :string
      add :utm_campaign, :string
      add :source, :string
      add :metadata, :map

      timestamps(updated_at: false)
    end

    create unique_index(:early_access_signups, [:email])
  end
end