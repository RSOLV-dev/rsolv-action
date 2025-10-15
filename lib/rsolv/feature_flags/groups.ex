defmodule Rsolv.FeatureFlags.Groups do
  @moduledoc """
  FunWithFlags.Group behavior implementation for role-based feature access.

  This module defines group membership for the RSOLV Landing feature flag system,
  supporting four user groups:
  - admin: Full access to all features
  - vip: Premium features including team collaboration and API access
  - phase_1: Advanced analytics, custom templates, and priority support
  - early_access: Basic features only (default group)

  Group membership is determined by:
  1. Email address (for admin users)
  2. User tags (for vip and phase_1 users)
  3. Default to early_access for all authenticated users
  """

  @behaviour FunWithFlags.Group

  @doc """
  Determines if an actor belongs to a specific group.

  ## Parameters
  - group: The group atom (:admin, :vip, :phase_1, :early_access)
  - actor: A map with at least an :id field (email) and optionally :tags

  ## Examples

      iex> in?(:admin, %{id: "admin@rsolv.dev"})
      true

      iex> in?(:vip, %{id: "user@example.com", tags: ["vip"]})
      true

      iex> in?(:phase_1, %{id: "user@example.com", tags: ["phase_1"]})
      true

      iex> in?(:early_access, %{id: "anyone@example.com"})
      true
  """
  @impl true
  def in?(group, actor)

  # Handle both string and atom group names
  def in?(group, actor) when is_binary(group) do
    in?(String.to_existing_atom(group), actor)
  rescue
    ArgumentError -> false
  end

  # Admin group - check email against admin list
  def in?(:admin, %{id: email}) when is_binary(email) do
    email in admin_emails()
  end

  # VIP group - check for vip tag
  def in?(:vip, %{tags: tags}) when is_list(tags) do
    "vip" in tags
  end

  def in?(:vip, %{id: email}) when is_binary(email) do
    # Also check if admin (admins have all permissions)
    email in admin_emails()
  end

  # Phase 1 group - check for phase_1 tag or higher tiers
  def in?(:phase_1, %{tags: tags}) when is_list(tags) do
    "phase_1" in tags or "vip" in tags
  end

  def in?(:phase_1, %{id: email, tags: tags}) when is_binary(email) and is_list(tags) do
    email in admin_emails() or "phase_1" in tags or "vip" in tags
  end

  def in?(:phase_1, %{id: email}) when is_binary(email) do
    email in admin_emails()
  end

  # Early access group - everyone with a valid actor
  def in?(:early_access, %{id: _}) do
    true
  end

  # Default case - not in group
  def in?(_, _) do
    false
  end

  # Private helper to get admin emails from configuration
  defp admin_emails do
    Application.get_env(:rsolv, :admin_emails, [
      "admin@rsolv.dev",
      "support@rsolv.dev"
    ])
  end

  @doc """
  Converts a user map from the FeatureFlags format to FunWithFlags actor format.

  ## Examples

      iex> to_actor(%{email: "user@example.com", tags: ["vip"]})
      %{id: "user@example.com", tags: ["vip"]}

      iex> to_actor(%{email: "user@example.com"})
      %{id: "user@example.com", tags: []}
  """
  def to_actor(%{email: email} = user) when is_binary(email) do
    %{
      id: email,
      tags: Map.get(user, :tags, [])
    }
  end

  def to_actor(nil), do: nil

  @doc """
  Lists all available groups in the system.
  """
  def all_groups do
    [:admin, :vip, :phase_1, :early_access]
  end

  @doc """
  Returns human-readable description for each group.
  """
  def group_description(group) do
    case group do
      :admin -> "Administrators with full system access"
      :vip -> "VIP users with premium features"
      :phase_1 -> "Phase 1 users with advanced features"
      :early_access -> "Early access users with basic features"
      _ -> "Unknown group"
    end
  end

  @doc """
  Returns the features available to each group.
  """
  def group_features(group) do
    case group do
      :admin ->
        [
          :interactive_roi_calculator,
          :team_size_field,
          :feedback_form,
          :early_access_signup,
          :welcome_email_sequence,
          :core_features,
          :advanced_analytics,
          :custom_templates,
          :team_collaboration,
          :api_access,
          :priority_support,
          :admin_dashboard,
          :metrics_dashboard,
          :feedback_dashboard,
          :support_ticket_submission,
          :user_engagement_tracking,
          :a_b_testing
        ]

      :vip ->
        [
          :interactive_roi_calculator,
          :team_size_field,
          :feedback_form,
          :early_access_signup,
          :welcome_email_sequence,
          :core_features,
          :advanced_analytics,
          :custom_templates,
          :team_collaboration,
          :api_access,
          :priority_support
        ]

      :phase_1 ->
        [
          :interactive_roi_calculator,
          :team_size_field,
          :feedback_form,
          :early_access_signup,
          :welcome_email_sequence,
          :core_features,
          :advanced_analytics,
          :custom_templates,
          :priority_support
        ]

      :early_access ->
        [
          :interactive_roi_calculator,
          :team_size_field,
          :feedback_form,
          :early_access_signup,
          :welcome_email_sequence,
          :core_features
        ]

      _ ->
        []
    end
  end
end
