defmodule Rsolv.EarlyAccess.Signup do
  use Ecto.Schema
  import Ecto.Changeset

  schema "early_access_signups" do
    field :email, :string
    field :name, :string
    field :company, :string
    field :referral_source, :string
    field :utm_source, :string
    field :utm_medium, :string
    field :utm_campaign, :string

    timestamps(updated_at: false)
  end

  @doc false
  def changeset(signup, attrs) do
    signup
    |> cast(attrs, [
      :email,
      :name,
      :company,
      :referral_source,
      :utm_source,
      :utm_medium,
      :utm_campaign
    ])
    |> validate_required([:email])
    |> validate_format(:email, ~r/^[^\s]+@[^\s]+$/, message: "must have the @ sign and no spaces")
    |> unique_constraint(:email)
  end
end
