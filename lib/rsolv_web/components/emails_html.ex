defmodule RsolvWeb.EmailsHTML do
  @moduledoc """
  Module for rendering email templates using Phoenix 1.7's approach.

  This module provides two types of functions for each email template:

  1. Template functions (e.g., `welcome/1`, `payment_failed/1`) - Return Phoenix LiveView
     compatible HTML content for direct use in HEEx templates.

  2. Render functions (e.g., `render_welcome/1`, `render_payment_failed/1`) - Apply default
     assigns and return safe HTML strings suitable for email delivery.

  All templates are loaded from the filesystem using `RsolvWeb.Email.TemplateLoader`,
  which provides production-safe path resolution.

  ## Available Templates

  #{Enum.map_join(~w(early_access_guide early_access_welcome feature_deep_dive feedback_request first_issue getting_started payment_failed setup_verification success_checkin welcome), "\n", &"  * #{&1}")}

  ## Examples

      # Use in HEEx templates
      <%= early_access_guide(assigns) %>

      # Use for email delivery
      html_body = render_early_access_guide(%{first_name: "Jane", email: "jane@example.com"})
  """
  use RsolvWeb, :html

  alias RsolvWeb.Email.TemplateLoader

  # List of all email templates that follow the standard pattern
  @templates ~w(
    early_access_guide
    early_access_welcome
    feature_deep_dive
    feedback_request
    first_issue
    getting_started
    payment_failed
    setup_verification
    success_checkin
    welcome
  )a

  # Helper function to make assigns available
  defp assign_new_lazy(assigns, key, fun) do
    if Map.has_key?(assigns, key) do
      assigns
    else
      Map.put(assigns, key, fun.())
    end
  end

  @doc """
  Adds default assigns to the provided assigns map.

  Default assigns include:
  - `:app_url` - "https://rsolv.dev"
  - `:docs_url` - "https://rsolv.dev/docs"
  - `:unsubscribe_url` - Personalized unsubscribe URL
  - `:first_name` - "there" (fallback greeting)
  - `:email` - "" (empty string fallback)

  ## Examples

      iex> RsolvWeb.EmailsHTML.with_defaults(%{email: "user@example.com"})
      %{
        email: "user@example.com",
        app_url: "https://rsolv.dev",
        docs_url: "https://rsolv.dev/docs",
        unsubscribe_url: "https://rsolv.dev/unsubscribe?email=user@example.com",
        first_name: "there"
      }
  """
  def with_defaults(assigns) do
    assigns
    |> assign_new_lazy(:app_url, fn -> "https://rsolv.dev" end)
    |> assign_new_lazy(:docs_url, fn -> "https://rsolv.dev/docs" end)
    |> assign_new_lazy(:unsubscribe_url, fn ->
      "https://rsolv.dev/unsubscribe?email=#{assigns[:email]}"
    end)
    |> assign_new_lazy(:first_name, fn -> "there" end)
    |> assign_new_lazy(:email, fn -> "" end)
  end

  # Generate template and render functions for each template using metaprogramming
  for template <- @templates do
    template_name = Atom.to_string(template)

    @doc """
    Renders the #{template_name} email template.

    Returns Phoenix LiveView compatible HTML content.

    ## Parameters

      * `assigns` - Map of template variables (unused in static templates)

    ## Examples

        iex> #{template}(assigns)
        {:safe, ...}
    """
    def unquote(template)(assigns) do
      template_content = TemplateLoader.load_template!(unquote(template_name))

      ~H"""
      {Phoenix.HTML.raw(template_content)}
      """
    end

    @doc """
    Renders the #{template_name} email template with default assigns applied.

    Returns a safe HTML string suitable for email delivery.

    ## Parameters

      * `assigns` - Map of template variables (e.g., `%{first_name: "Jane", email: "jane@example.com"}`)

    ## Examples

        iex> render_#{template}(%{first_name: "Jane", email: "jane@example.com"})
        "<html>...</html>"
    """
    def unquote(:"render_#{template}")(assigns) do
      assigns = with_defaults(assigns)
      html = unquote(template)(assigns)
      Phoenix.HTML.Safe.to_iodata(html) |> IO.iodata_to_binary()
    end
  end
end
