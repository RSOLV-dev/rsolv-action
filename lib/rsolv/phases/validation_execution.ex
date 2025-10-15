defmodule Rsolv.Phases.ValidationExecution do
  use Ecto.Schema
  import Ecto.Changeset

  schema "validation_executions" do
    field :issue_number, :integer
    field :commit_sha, :string
    field :status, Ecto.Enum, values: [:pending, :running, :completed, :failed], default: :pending
    field :validated, :boolean
    field :vulnerabilities_found, :integer
    field :data, :map, default: %{}
    field :started_at, :utc_datetime_usec
    field :completed_at, :utc_datetime_usec
    field :error_message, :string

    belongs_to :repository, Rsolv.Phases.Repository
    belongs_to :api_key, Rsolv.Customers.ApiKey

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields [:repository_id, :issue_number, :commit_sha, :data]
  @optional_fields [
    :status,
    :validated,
    :vulnerabilities_found,
    :started_at,
    :completed_at,
    :error_message,
    :api_key_id
  ]

  def changeset(validation_execution, attrs) do
    validation_execution
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:status, [:pending, :running, :completed, :failed])
    |> validate_number(:issue_number, greater_than: 0)
    |> put_started_at_if_running()
    |> put_completed_at_if_done()
    |> extract_validation_result()
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

  defp extract_validation_result(changeset) do
    case get_change(changeset, :data) do
      %{"validated" => validated, "vulnerabilities" => vulnerabilities}
      when is_list(vulnerabilities) ->
        changeset
        |> put_change(:validated, validated)
        |> put_change(:vulnerabilities_found, length(vulnerabilities))

      _ ->
        changeset
    end
  end
end
