defmodule Rsolv.Phases.ForgeAccount do
  use Ecto.Schema
  import Ecto.Changeset

  schema "forge_accounts" do
    field :forge_type, Ecto.Enum, values: [:github]
    field :namespace, :string
    field :verified_at, :utc_datetime_usec
    field :metadata, :map, default: %{}
    
    belongs_to :customer, Rsolv.Customers.Customer
    
    timestamps(type: :utc_datetime_usec)
  end

  @required_fields [:forge_type, :namespace, :customer_id]
  @optional_fields [:verified_at, :metadata]

  def changeset(forge_account, attrs) do
    forge_account
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:forge_type, [:github])
    |> validate_format(:namespace, ~r/^[a-zA-Z0-9][a-zA-Z0-9-_]*$/, 
         message: "must contain only alphanumeric characters, hyphens, and underscores")
    |> unique_constraint([:customer_id, :forge_type, :namespace])
  end
end