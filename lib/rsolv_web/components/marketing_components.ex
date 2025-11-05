defmodule RsolvWeb.MarketingComponents do
  @moduledoc """
  Reusable components for marketing pages (landing, pricing, etc.).

  These components are optimized for marketing pages with centered layouts,
  full SVG icons, and gradient backgrounds. They differ from the standard
  `RsolvWeb.Components.FeatureCard` which is designed for blog/docs pages
  with border-top cards and letter icons.

  ## Component Relationships

  - `feature_card/1` - Marketing-style centered card with full SVG icon
  - `RsolvWeb.Components.FeatureCard` - Blog/docs-style card with border and letter icon
  - Uses `DarkModeHelpers` for consistent dark mode styling
  """
  use Phoenix.Component
  import RsolvWeb.Components.DarkModeHelpers

  @doc """
  Renders a feature card with icon, title, and description.

  ## Examples

      <.feature_card
        icon="check-circle"
        title="Real Vulnerabilities"
        description="Not false positives - only actionable security issues"
      />
  """
  attr :icon, :string, required: true, doc: "SVG path for the icon"
  attr :title, :string, required: true
  attr :description, :string, required: true
  attr :class, :string, default: ""

  def feature_card(assigns) do
    ~H"""
    <div class={"text-center #{@class}"}>
      <div class="mb-4 flex justify-center">
        <%= Phoenix.HTML.raw(@icon) %>
      </div>
      <h3 class={text_classes(:heading, "text-xl font-semibold mb-2")}><%= @title %></h3>
      <p class={text_classes(:muted)}><%= @description %></p>
    </div>
    """
  end

  @doc """
  Renders a primary CTA button with tracking.

  ## Examples

      <.cta_button
        navigate="/signup"
        track_destination="/signup"
        variant="primary"
      >
        Start Free Trial
      </.cta_button>
  """
  attr :navigate, :string, default: nil
  attr :href, :string, default: nil
  attr :track_destination, :string, required: true
  attr :variant, :string, default: "primary", values: ~w(primary secondary)
  attr :size, :string, default: "large", values: ~w(small large)
  attr :class, :string, default: ""
  slot :inner_block, required: true

  def cta_button(assigns) do
    assigns = assign_button_classes(assigns)

    ~H"""
    <%= if @navigate do %>
      <.link
        navigate={@navigate}
        phx-click="track_cta_click"
        phx-value-destination={@track_destination}
        class={@button_class}
      >
        <%= render_slot(@inner_block) %>
      </.link>
    <% else %>
      <a
        href={@href}
        phx-click="track_cta_click"
        phx-value-destination={@track_destination}
        class={@button_class}
        {if @href =~ "http", do: [target: "_blank", rel: "noopener noreferrer"], else: []}
      >
        <%= render_slot(@inner_block) %>
      </a>
    <% end %>
    """
  end

  defp assign_button_classes(assigns) do
    base_class = "inline-block font-semibold rounded-lg transition-colors duration-200"

    size_class =
      case assigns.size do
        "small" -> "px-6 py-3"
        "large" -> "px-8 py-4 text-lg"
      end

    variant_class =
      case assigns.variant do
        "primary" ->
          "bg-blue-600 text-white hover:bg-blue-700 shadow-lg"

        "secondary" ->
          "bg-gray-200 dark:bg-gray-700 text-gray-900 dark:text-gray-100 hover:bg-gray-300 dark:hover:bg-gray-600"
      end

    button_class = "#{base_class} #{size_class} #{variant_class} #{assigns.class}"
    assign(assigns, :button_class, button_class)
  end

  @doc """
  Renders a stat/metric display for social proof.

  ## Examples

      <.stat number="1000+" label="Vulnerabilities Fixed" />
  """
  attr :number, :string, required: true
  attr :label, :string, required: true
  attr :class, :string, default: ""

  def stat(assigns) do
    ~H"""
    <div class={@class}>
      <div class="text-4xl font-bold text-blue-600 dark:text-blue-400 mb-2"><%= @number %></div>
      <div class={text_classes(:muted)}><%= @label %></div>
    </div>
    """
  end

  @doc """
  Renders a gradient section background (used for hero and CTA sections).
  """
  attr :class, :string, default: ""
  attr :padding, :string, default: "py-20"
  slot :inner_block, required: true

  def gradient_section(assigns) do
    ~H"""
    <section class={"relative bg-gradient-to-br from-blue-600 to-emerald-600 dark:from-blue-700 dark:to-emerald-700 text-white px-4 sm:px-6 lg:px-8 #{@padding} #{@class}"}>
      <div class="container mx-auto max-w-6xl">
        <%= render_slot(@inner_block) %>
      </div>
    </section>
    """
  end
end
