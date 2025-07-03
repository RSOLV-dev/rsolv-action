defmodule Rsolv.Repo.Migrations.MakeIssueNumberNullable do
  use Ecto.Migration

  def change do
    alter table(:fix_attempts) do
      modify :issue_number, :integer, null: true, from: {:integer, null: false}
    end
  end
end