defmodule RsolvWeb.Components.Marketing.GradientDecoration do
  @moduledoc """
  Reusable gradient decoration elements for marketing components.

  Provides consistent decorative gradient blur effects adapted from Tailwind Plus.
  These decorations add visual polish to marketing pages without interfering with content.

  ## Usage

      # Polygon gradient (top position)
      <GradientDecoration.gradient_blur position={:top} />

      # Polygon gradient (bottom position)
      <GradientDecoration.gradient_blur position={:bottom} />

      # Radial gradient (for CTA sections)
      <GradientDecoration.gradient_blur variant={:radial} />

  """
  use Phoenix.Component

  @doc """
  Renders a decorative gradient blur element.

  ## Attributes

  - `position` - :top or :bottom (default: :top) - Controls vertical positioning of polygon gradients
  - `variant` - :polygon or :radial (default: :polygon) - Type of gradient decoration
  - `from_color` - Starting gradient color (default: "blue-600")
  - `to_color` - Ending gradient color (default: "emerald-600")
  - `opacity` - Gradient opacity (default: "30")

  ## Examples

      # Default top polygon gradient
      <.gradient_blur />

      # Bottom polygon gradient
      <.gradient_blur position={:bottom} />

      # Radial gradient for CTA sections
      <.gradient_blur variant={:radial} />

      # Custom colors
      <.gradient_blur from_color="purple-600" to_color="pink-600" />
  """
  attr :position, :atom, default: :top
  attr :variant, :atom, default: :polygon
  attr :from_color, :string, default: "blue-600"
  attr :to_color, :string, default: "emerald-600"
  attr :opacity, :string, default: "30"

  def gradient_blur(assigns) do
    assigns = assign_gradient_classes(assigns)

    ~H"""
    <%= if @variant == :polygon do %>
      <!-- Polygon gradient decoration with clip-path -->
      <div aria-hidden="true" class={@wrapper_class}>
        <div style={"clip-path: #{@clip_path}"} class={@gradient_class}></div>
      </div>
    <% else %>
      <!-- Radial gradient decoration (SVG) -->
      <svg viewBox="0 0 1024 1024" aria-hidden="true" class={@svg_class}>
        <circle r="512" cx="512" cy="512" fill="url(#gradient-decoration)" fill-opacity="0.7">
        </circle>
        <defs>
          <radialGradient id="gradient-decoration">
            <stop stop-color={"##{gradient_color_to_hex(@from_color)}"}></stop>
            <stop offset="1" stop-color={"##{gradient_color_to_hex(@to_color)}"}></stop>
          </radialGradient>
        </defs>
      </svg>
    <% end %>
    """
  end

  # Private functions

  defp assign_gradient_classes(assigns) do
    position = assigns.position
    variant = assigns.variant
    from_color = assigns.from_color
    to_color = assigns.to_color
    opacity = assigns.opacity

    # Complex polygon clip-path from Tailwind Plus
    clip_path =
      "polygon(74.1% 44.1%, 100% 61.6%, 97.5% 26.9%, 85.5% 0.1%, 80.7% 2%, 72.5% 32.5%, 60.2% 62.4%, 52.4% 68.1%, 47.5% 58.3%, 45.2% 34.5%, 27.5% 76.7%, 0.1% 64.9%, 17.9% 100%, 27.6% 76.8%, 76.1% 97.7%, 74.1% 44.1%)"

    {wrapper_class, gradient_class} =
      case {position, variant} do
        {:top, :polygon} ->
          {
            "absolute inset-x-0 -top-40 -z-10 transform-gpu overflow-hidden blur-3xl sm:-top-80",
            "relative left-[calc(50%-11rem)] aspect-[1155/678] w-[36.125rem] -translate-x-1/2 rotate-[30deg] bg-gradient-to-tr from-#{from_color} to-#{to_color} opacity-#{opacity} sm:left-[calc(50%-30rem)] sm:w-[72.1875rem]"
          }

        {:bottom, :polygon} ->
          {
            "absolute inset-x-0 top-[calc(100%-13rem)] -z-10 transform-gpu overflow-hidden blur-3xl sm:top-[calc(100%-30rem)]",
            "relative left-[calc(50%+3rem)] aspect-[1155/678] w-[36.125rem] -translate-x-1/2 bg-gradient-to-tr from-#{from_color} to-#{to_color} opacity-#{opacity} sm:left-[calc(50%+36rem)] sm:w-[72.1875rem]"
          }

        {_, :radial} ->
          {nil, nil}
      end

    svg_class =
      "absolute top-1/2 left-1/2 -z-10 size-256 -translate-y-1/2 [mask-image:radial-gradient(closest-side,white,transparent)] sm:left-full sm:-ml-80 lg:left-1/2 lg:ml-0 lg:-translate-x-1/2 lg:translate-y-0"

    assigns
    |> assign(:clip_path, clip_path)
    |> assign(:wrapper_class, wrapper_class)
    |> assign(:gradient_class, gradient_class)
    |> assign(:svg_class, svg_class)
  end

  # Convert Tailwind color name to hex for SVG
  defp gradient_color_to_hex("blue-600"), do: "3B82F6"
  defp gradient_color_to_hex("blue-500"), do: "3B82F6"
  defp gradient_color_to_hex("emerald-600"), do: "10B981"
  defp gradient_color_to_hex("emerald-500"), do: "10B981"
  defp gradient_color_to_hex("purple-600"), do: "9333EA"
  defp gradient_color_to_hex("pink-600"), do: "DB2777"
  # Default to blue if unknown
  defp gradient_color_to_hex(_), do: "3B82F6"
end
