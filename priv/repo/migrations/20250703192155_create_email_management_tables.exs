defmodule Rsolv.Repo.Migrations.CreateEmailManagementTables do
  use Ecto.Migration

  def change do
    create table(:email_unsubscribes) do
      add :email, :string, null: false
      add :reason, :text
      
      timestamps(updated_at: false)
    end

    create unique_index(:email_unsubscribes, [:email])

    create table(:failed_emails) do
      add :to_email, :string, null: false
      add :subject, :string
      add :template, :string
      add :error_message, :text
      add :email_data, :map
      add :attempts, :integer, default: 1
      
      timestamps()
    end

    create index(:failed_emails, [:inserted_at])
    create index(:failed_emails, [:to_email])
  end
end