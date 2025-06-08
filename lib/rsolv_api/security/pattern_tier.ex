defmodule RsolvApi.Security.PatternTier do
  use Ecto.Schema
  import Ecto.Changeset

  schema "pattern_tiers" do
    field :name, :string
    field :description, :string
    field :auth_required, :boolean, default: false
    field :api_key_required, :boolean, default: false
    field :enterprise_required, :boolean, default: false
    field :ai_flag_required, :boolean, default: false
    field :display_order, :integer, default: 0

    has_many :security_patterns, RsolvApi.Security.SecurityPattern

    timestamps()
  end

  @doc false
  def changeset(pattern_tier, attrs) do
    pattern_tier
    |> cast(attrs, [:name, :description, :auth_required, :api_key_required, 
                    :enterprise_required, :ai_flag_required, :display_order])
    |> validate_required([:name])
    |> unique_constraint(:name)
  end

  @doc """
  Get tier by name
  """
  def get_tier_by_name(name) do
    case name do
      "public" -> %{auth_required: false, api_key_required: false, enterprise_required: false, ai_flag_required: false}
      "protected" -> %{auth_required: true, api_key_required: true, enterprise_required: false, ai_flag_required: false}
      "ai" -> %{auth_required: true, api_key_required: true, enterprise_required: false, ai_flag_required: true}
      "enterprise" -> %{auth_required: true, api_key_required: true, enterprise_required: true, ai_flag_required: false}
      _ -> nil
    end
  end
end