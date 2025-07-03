defmodule Rsolv.EmailManagement.FailedEmail do
  use Ecto.Schema
  import Ecto.Changeset

  schema "failed_emails" do
    field :to_email, :string
    field :subject, :string
    field :template, :string
    field :error_message, :string
    field :email_data, :map
    field :attempts, :integer, default: 1

    timestamps()
  end

  @doc false
  def changeset(failed_email, attrs) do
    failed_email
    |> cast(attrs, [:to_email, :subject, :template, :error_message, :email_data, :attempts])
    |> validate_required([:to_email])
    |> validate_number(:attempts, greater_than: 0)
  end
end