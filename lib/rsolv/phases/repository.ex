defmodule Rsolv.Phases.Repository do
  use Ecto.Schema
  import Ecto.Changeset

  schema "repositories" do
    field :forge_type, Ecto.Enum, values: [:github]
    field :namespace, :string
    field :name, :string
    field :full_path, :string
    field :first_seen_at, :utc_datetime_usec
    field :last_activity_at, :utc_datetime_usec
    field :metadata, :map, default: %{}

    belongs_to :customer, Rsolv.Customers.Customer
    has_many :scan_executions, Rsolv.Phases.ScanExecution
    has_many :validation_executions, Rsolv.Phases.ValidationExecution
    has_many :mitigation_executions, Rsolv.Phases.MitigationExecution

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields [:forge_type, :namespace, :name]
  @optional_fields [:customer_id, :metadata]

  def changeset(repository, attrs) do
    repository
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:forge_type, [:github])
    |> put_full_path()
    |> put_timestamps_if_new()
    |> unique_constraint([:forge_type, :namespace, :name])
  end

  defp put_full_path(changeset) do
    case {get_field(changeset, :namespace), get_field(changeset, :name)} do
      {nil, _} -> changeset
      {_, nil} -> changeset
      {namespace, name} -> put_change(changeset, :full_path, "#{namespace}/#{name}")
    end
  end

  defp put_timestamps_if_new(changeset) do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    changeset
    |> put_change_if_nil(:first_seen_at, now)
    |> put_change(:last_activity_at, now)
  end

  defp put_change_if_nil(changeset, field, value) do
    if get_field(changeset, field) == nil do
      put_change(changeset, field, value)
    else
      changeset
    end
  end
end
