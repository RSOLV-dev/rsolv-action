defmodule Rsolv.Marketing.EmailSubscription do
  use Ecto.Schema
  import Ecto.Changeset

  schema "email_subscriptions" do
    field :email, :string
    field :source, :string
    field :status, :string, default: "active"
    field :tags, {:array, :string}, default: []
    field :convertkit_subscriber_id, :string
    field :unsubscribed_at, :naive_datetime

    # TODO: Replace with actual user schema when implemented
    # belongs_to :user, Rsolv.Accounts.User
    field :user_id, :integer

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(email_subscription, attrs) do
    email_subscription
    |> cast(attrs, [:email, :user_id, :source, :status, :tags, :convertkit_subscriber_id, :unsubscribed_at])
    |> validate_required([:email])
    |> validate_format(:email, ~r/^[^\s]+@[^\s]+$/, message: "must have the @ sign and no spaces")
    |> validate_inclusion(:status, ["active", "unsubscribed", "bounced"])
    |> unique_constraint(:email)
  end
end