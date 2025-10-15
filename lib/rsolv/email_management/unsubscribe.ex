defmodule Rsolv.EmailManagement.Unsubscribe do
  use Ecto.Schema
  import Ecto.Changeset

  schema "email_unsubscribes" do
    field :email, :string
    field :reason, :string

    timestamps(updated_at: false)
  end

  @doc false
  def changeset(unsubscribe, attrs) do
    unsubscribe
    |> cast(attrs, [:email, :reason])
    |> validate_required([:email])
    |> validate_format(:email, ~r/^[^\s]+@[^\s]+$/, message: "must have the @ sign and no spaces")
    |> unique_constraint(:email)
  end
end
