defmodule RSOLV.Accounts.Customer do
  @moduledoc """
  Customer schema for API access and billing.
  """
  use Ecto.Schema
  import Ecto.Changeset

  schema "customers" do
    field :name, :string
    field :email, :string
    field :api_key, :string
    field :tier, :string, default: "teams"
    field :ai_enabled, :boolean, default: false
    field :is_active, :boolean, default: true
    field :metadata, :map, default: %{}

    timestamps()
  end

  @doc false
  def changeset(customer, attrs) do
    customer
    |> cast(attrs, [:name, :email, :api_key, :tier, :ai_enabled, :is_active, :metadata])
    |> validate_required([:name, :api_key, :tier])
    |> validate_inclusion(:tier, ["basic", "teams", "enterprise"])
    |> unique_constraint(:api_key)
    |> unique_constraint(:email)
    |> generate_api_key()
  end

  defp generate_api_key(changeset) do
    if get_change(changeset, :api_key) == nil do
      put_change(changeset, :api_key, "rsolv_#{random_string(32)}")
    else
      changeset
    end
  end

  defp random_string(length) do
    :crypto.strong_rand_bytes(length)
    |> Base.url_encode64()
    |> binary_part(0, length)
  end
end