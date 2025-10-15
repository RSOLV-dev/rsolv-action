defmodule Rsolv.ValidationCache.CachedValidation do
  use Ecto.Schema
  import Ecto.Changeset

  @moduledoc """
  Schema for cached vulnerability validation results.

  Stores false positive determinations to avoid re-validating
  the same vulnerabilities repeatedly.
  """

  schema "cached_validations" do
    field :cache_key, :string
    field :repository, :string
    field :vulnerability_type, :string
    field :locations, {:array, :map}
    field :file_hashes, :map

    # Validation result
    field :is_false_positive, :boolean
    field :confidence, :decimal
    field :reason, :string
    field :full_result, :map

    # Metadata
    field :cached_at, :utc_datetime_usec
    field :ttl_expires_at, :utc_datetime_usec
    field :invalidated_at, :utc_datetime_usec
    field :invalidation_reason, :string

    # Changed from belongs_to to support both integer and string IDs (for test accounts)
    field :forge_account_id, :string

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields [
    :cache_key,
    :forge_account_id,
    :repository,
    :vulnerability_type,
    :locations,
    :file_hashes,
    :is_false_positive,
    :confidence,
    :cached_at,
    :ttl_expires_at
  ]
  @optional_fields [:reason, :full_result, :invalidated_at, :invalidation_reason]

  @doc """
  Creates a changeset for a cached validation entry.
  """
  def changeset(cached_validation, attrs) do
    cached_validation
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_number(:confidence, greater_than_or_equal_to: 0, less_than_or_equal_to: 1)
    |> validate_inclusion(:invalidation_reason, ["file_change", "ttl_expired", "manual"])
    |> unique_constraint(:cache_key)
  end
end
