defmodule RsolvWeb.Helpers.FeatureHelpers do
  @moduledoc """
  Helper functions for working with feature flags in templates and views.
  
  These helpers provide a convenient way to check if features are enabled
  in templates and views, making it easy to conditionally render UI elements.
  """
  
  alias Rsolv.FeatureFlags
  
  @doc """
  Check if a feature is enabled.
  
  This is a wrapper around `Rsolv.FeatureFlags.enabled?/2` that can be used
  in templates and views.
  
  ## Examples
  
      <%= if feature_enabled?(:admin_dashboard, conn.assigns.current_user) do %>
        <div class="admin-dashboard">...</div>
      <% end %>
  """
  def feature_enabled?(feature, user \\ nil) do
    cond do
      is_nil(user) ->
        FeatureFlags.enabled?(feature)
        
      is_map(user) ->
        FeatureFlags.enabled?(feature, user: user)
        
      is_atom(user) and user in [:admin, :early_access] ->
        FeatureFlags.enabled?(feature, role: user)
        
      true ->
        FeatureFlags.enabled?(feature)
    end
  end
  
  @doc """
  Conditionally render content based on a feature flag.
  
  This function takes a feature flag name, a user (or role), and two functions:
  one to execute if the feature is enabled, and another to execute if it's disabled.
  
  ## Examples
  
      <%= feature_toggle :admin_dashboard, conn.assigns.current_user do %>
        <div class="admin-dashboard">...</div>
      <% else %>
        <div class="access-denied">...</div>
      <% end %>
  """
  defmacro feature_toggle(feature, user \\ nil, opts)
  
  defmacro feature_toggle(feature, user, do: do_block, else: else_block) do
    quote do
      if RsolvWeb.Helpers.FeatureHelpers.feature_enabled?(unquote(feature), unquote(user)) do
        unquote(do_block)
      else
        unquote(else_block)
      end
    end
  end
  
  defmacro feature_toggle(feature, user, do: do_block) do
    quote do
      if RsolvWeb.Helpers.FeatureHelpers.feature_enabled?(unquote(feature), unquote(user)) do
        unquote(do_block)
      end
    end
  end
end