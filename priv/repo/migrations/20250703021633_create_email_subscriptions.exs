defmodule Rsolv.Repo.Migrations.CreateEmailSubscriptions do
  use Ecto.Migration

  def change do
    create table(:email_subscriptions) do
      add :email, :citext, null: false
      add :user_id, references(:users, on_delete: :nilify_all)
      add :source, :string
      add :status, :string, default: "active"
      add :tags, {:array, :string}, default: []
      add :convertkit_subscriber_id, :string
      add :unsubscribed_at, :naive_datetime
      
      timestamps(type: :utc_datetime)
    end

    create unique_index(:email_subscriptions, [:email])
    create index(:email_subscriptions, [:user_id])
    create index(:email_subscriptions, [:status])
    create index(:email_subscriptions, [:convertkit_subscriber_id])
  end
end