defmodule Rsolv.Repo.Migrations.CreatePhaseExecutions do
  use Ecto.Migration

  def change do
    # Create enum for execution status
    execute """
      CREATE TYPE execution_status AS ENUM ('pending', 'running', 'completed', 'failed')
    """, """
      DROP TYPE execution_status
    """

    # Create scan_executions table
    create table(:scan_executions) do
      add :repository_id, references(:repositories, on_delete: :delete_all), null: false
      add :commit_sha, :string, null: false
      add :branch, :string
      add :status, :execution_status, null: false, default: "pending"
      add :vulnerabilities_count, :integer
      add :data, :jsonb, null: false, default: "{}"
      add :started_at, :utc_datetime_usec
      add :completed_at, :utc_datetime_usec
      add :error_message, :text
      add :api_key_id, references(:api_keys, on_delete: :nilify_all)
      
      timestamps(type: :utc_datetime_usec)
    end

    # Create validation_executions table
    create table(:validation_executions) do
      add :repository_id, references(:repositories, on_delete: :delete_all), null: false
      add :issue_number, :integer, null: false  # Required for validation
      add :commit_sha, :string, null: false
      add :status, :execution_status, null: false, default: "pending"
      add :validated, :boolean
      add :vulnerabilities_found, :integer
      add :data, :jsonb, null: false, default: "{}"
      add :started_at, :utc_datetime_usec
      add :completed_at, :utc_datetime_usec
      add :error_message, :text
      add :api_key_id, references(:api_keys, on_delete: :nilify_all)
      
      timestamps(type: :utc_datetime_usec)
    end

    # Create mitigation_executions table
    create table(:mitigation_executions) do
      add :repository_id, references(:repositories, on_delete: :delete_all), null: false
      add :issue_number, :integer, null: false  # Required for mitigation
      add :commit_sha, :string, null: false
      add :status, :execution_status, null: false, default: "pending"
      add :pr_url, :string
      add :pr_number, :integer
      add :files_changed, :integer
      add :data, :jsonb, null: false, default: "{}"
      add :started_at, :utc_datetime_usec
      add :completed_at, :utc_datetime_usec
      add :error_message, :text
      add :api_key_id, references(:api_keys, on_delete: :nilify_all)
      
      timestamps(type: :utc_datetime_usec)
    end

    # Indexes for scan_executions
    create index(:scan_executions, [:repository_id])
    create index(:scan_executions, [:commit_sha])
    create index(:scan_executions, [:status])
    create index(:scan_executions, [:inserted_at])

    # Indexes for validation_executions
    create index(:validation_executions, [:repository_id])
    create index(:validation_executions, [:issue_number])
    create index(:validation_executions, [:commit_sha])
    create index(:validation_executions, [:status])
    create index(:validation_executions, [:repository_id, :issue_number, :commit_sha])

    # Indexes for mitigation_executions
    create index(:mitigation_executions, [:repository_id])
    create index(:mitigation_executions, [:issue_number])
    create index(:mitigation_executions, [:commit_sha])
    create index(:mitigation_executions, [:status])
    create index(:mitigation_executions, [:repository_id, :issue_number, :commit_sha])

    # GIN indexes for JSONB queries
    execute "CREATE INDEX scan_executions_data_gin ON scan_executions USING GIN (data)",
            "DROP INDEX scan_executions_data_gin"
    execute "CREATE INDEX validation_executions_data_gin ON validation_executions USING GIN (data)",
            "DROP INDEX validation_executions_data_gin"
    execute "CREATE INDEX mitigation_executions_data_gin ON mitigation_executions USING GIN (data)",
            "DROP INDEX mitigation_executions_data_gin"
  end
end