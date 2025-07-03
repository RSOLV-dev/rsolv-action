defmodule Rsolv.Repo.Migrations.CreateFeedbackTables do
  use Ecto.Migration

  def change do
    create table(:feedback_entries) do
      add :email, :string
      add :message, :text
      add :rating, :integer
      add :tags, {:array, :string}, default: []
      add :source, :string
      add :content, :map, default: %{}
      add :metadata, :map, default: %{}

      timestamps()
    end

    create index(:feedback_entries, [:email])
    create index(:feedback_entries, [:inserted_at])
  end
end