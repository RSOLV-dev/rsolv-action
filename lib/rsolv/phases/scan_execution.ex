defmodule Rsolv.Phases.ScanExecution do
  use Ecto.Schema
  import Ecto.Changeset

  schema "scan_executions" do
    field :commit_sha, :string
    field :branch, :string
    field :status, Ecto.Enum, values: [:pending, :running, :completed, :failed], default: :pending
    field :vulnerabilities_count, :integer
    field :data, :map, default: %{}
    field :started_at, :utc_datetime_usec
    field :completed_at, :utc_datetime_usec
    field :error_message, :string

    belongs_to :repository, Rsolv.Phases.Repository
    belongs_to :api_key, Rsolv.Customers.ApiKey

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields [:repository_id, :commit_sha, :data]
  @optional_fields [
    :branch,
    :status,
    :vulnerabilities_count,
    :started_at,
    :completed_at,
    :error_message,
    :api_key_id
  ]

  def changeset(scan_execution, attrs) do
    scan_execution
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:status, [:pending, :running, :completed, :failed])
    |> put_started_at_if_running()
    |> put_completed_at_if_done()
    |> extract_vulnerabilities_count()
  end

  defp put_started_at_if_running(changeset) do
    if get_change(changeset, :status) == :running and get_field(changeset, :started_at) == nil do
      put_change(changeset, :started_at, DateTime.utc_now() |> DateTime.truncate(:microsecond))
    else
      changeset
    end
  end

  defp put_completed_at_if_done(changeset) do
    status = get_change(changeset, :status)

    if status in [:completed, :failed] and get_field(changeset, :completed_at) == nil do
      put_change(changeset, :completed_at, DateTime.utc_now() |> DateTime.truncate(:microsecond))
    else
      changeset
    end
  end

  defp extract_vulnerabilities_count(changeset) do
    case get_change(changeset, :data) do
      %{"vulnerabilities" => vulnerabilities} when is_list(vulnerabilities) ->
        put_change(changeset, :vulnerabilities_count, length(vulnerabilities))

      _ ->
        changeset
    end
  end
end
