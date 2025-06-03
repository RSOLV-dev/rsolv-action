defmodule RsolvApi.Billing.FixAttempt do
  @moduledoc """
  Tracks RSOLV-generated pull requests for billing purposes.
  Records PR creation, merge status, and billing state.
  """
  
  use Ecto.Schema
  import Ecto.Changeset

  schema "fix_attempts" do
    field :github_org, :string
    field :repo_name, :string
    field :issue_number, :integer
    field :pr_number, :integer
    field :status, :string  # pending, merged, rejected, timeout
    field :merged_at, :utc_datetime_usec
    field :billing_status, :string, default: "not_billed"  # not_billed, billed, refunded, disputed
    field :requires_manual_approval, :boolean, default: true
    field :approved_by, :string
    field :approved_at, :utc_datetime_usec
    field :approval_notes, :string
    field :platform, :string, default: "github"
    field :customer_id, :integer
    field :api_key_used, :string
    field :pr_title, :string
    field :pr_url, :string
    field :issue_title, :string
    field :issue_url, :string
    field :commit_sha, :string
    field :merged_by, :string
    field :metadata, :map, default: %{}
    field :amount, :decimal
    field :currency, :string, default: "USD"
    field :billed_at, :utc_datetime_usec
    field :refunded_at, :utc_datetime_usec

    timestamps()
  end

  @required_fields ~w(github_org repo_name pr_number status)a
  @optional_fields ~w(issue_number merged_at billing_status 
                     requires_manual_approval approved_by approved_at approval_notes
                     platform customer_id api_key_used pr_title pr_url issue_title
                     issue_url commit_sha merged_by metadata amount currency
                     billed_at refunded_at)a

  def changeset(fix_attempt, attrs) do
    fix_attempt
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:status, ~w(pending merged rejected timeout))
    |> validate_inclusion(:billing_status, ~w(not_billed billed refunded disputed))
  end
end