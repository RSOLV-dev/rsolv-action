defmodule Rsolv.Feedback.Entry do
  use Ecto.Schema
  import Ecto.Changeset

  schema "feedback_entries" do
    field :email, :string
    field :message, :string
    field :rating, :integer
    field :tags, {:array, :string}, default: []
    field :source, :string
    field :content, :map, default: %{}
    field :metadata, :map, default: %{}

    timestamps()
  end

  @doc false
  def changeset(entry, attrs) do
    entry
    |> cast(attrs, [:email, :message, :rating, :tags, :source, :content, :metadata])
    # Only source is required
    |> validate_required([:source])
    |> validate_format(:email, ~r/^[^\s]+@[^\s]+$/,
      message: "must have the @ sign and no spaces",
      allow_nil: true,
      allow_blank: true
    )
    |> validate_number(:rating, greater_than_or_equal_to: 1, less_than_or_equal_to: 5)
  end
end
