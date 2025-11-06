defmodule RsolvWeb.Components.Marketing.Icons do
  @moduledoc """
  Marketing icon library with common SVG icons from Tailwind Plus.

  Provides pre-defined Heroicons for use in marketing components.
  All icons are optimized for accessibility with proper aria attributes.

  ## Usage

      # In a component:
      {Phoenix.HTML.raw(Icons.checkmark(color: "text-blue-600"))}

      # In features list:
      features = [
        %{
          icon: Icons.checkmark_circle(color: "text-white"),
          title: "Real Vulnerabilities",
          description: "..."
        }
      ]

  ## Available Icons

  - `checkmark/1` - Checkmark icon (for feature lists)
  - `checkmark_circle/1` - Checkmark in circle (for feature highlights)
  - `lock/1` - Padlock icon (for security features)
  - `lightning/1` - Lightning bolt (for speed/performance)
  - `chart_up/1` - Ascending chart (for growth/analytics)
  - `shield/1` - Shield icon (for security)
  - `code/1` - Code brackets (for development)
  - `rocket/1` - Rocket icon (for launch/deployment)
  """

  @doc """
  Checkmark icon - commonly used in feature lists.

  ## Options

  - `:color` - Tailwind color class (default: "text-blue-600")
  - `:size` - Size class (default: "h-6 w-5")
  - `:extra_classes` - Additional CSS classes

  ## Examples

      Icons.checkmark()
      Icons.checkmark(color: "text-green-600")
      Icons.checkmark(color: "text-white", size: "h-8 w-6")
  """
  def checkmark(opts \\ []) do
    color = Keyword.get(opts, :color, "text-blue-600")
    size = Keyword.get(opts, :size, "h-6 w-5")
    extra_classes = Keyword.get(opts, :extra_classes, "")

    """
    <svg
      viewBox="0 0 20 20"
      fill="currentColor"
      aria-hidden="true"
      class="#{size} flex-none #{color} #{extra_classes}"
    >
      <path
        d="M16.704 4.153a.75.75 0 0 1 .143 1.052l-8 10.5a.75.75 0 0 1-1.127.075l-4.5-4.5a.75.75 0 0 1 1.06-1.06l3.894 3.893 7.48-9.817a.75.75 0 0 1 1.05-.143Z"
        clip-rule="evenodd"
        fill-rule="evenodd"
      />
    </svg>
    """
  end

  @doc """
  Checkmark in circle icon - for feature highlights.

  ## Options

  - `:color` - Tailwind color class (default: "text-white")
  - `:size` - Size class (default: "size-6")
  - `:stroke_width` - SVG stroke width (default: "1.5")

  ## Examples

      Icons.checkmark_circle()
      Icons.checkmark_circle(color: "text-blue-600")
  """
  def checkmark_circle(opts \\ []) do
    color = Keyword.get(opts, :color, "text-white")
    size = Keyword.get(opts, :size, "size-6")
    stroke_width = Keyword.get(opts, :stroke_width, "1.5")
    extra_classes = Keyword.get(opts, :extra_classes, "")

    """
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="#{stroke_width}"
      aria-hidden="true"
      class="#{size} #{color} #{extra_classes}"
    >
      <path
        stroke-linecap="round"
        stroke-linejoin="round"
        d="M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z"
      />
    </svg>
    """
  end

  @doc """
  Padlock icon - for security features.

  ## Options

  - `:color` - Tailwind color class (default: "text-white")
  - `:size` - Size class (default: "size-6")
  - `:stroke_width` - SVG stroke width (default: "1.5")
  """
  def lock(opts \\ []) do
    color = Keyword.get(opts, :color, "text-white")
    size = Keyword.get(opts, :size, "size-6")
    stroke_width = Keyword.get(opts, :stroke_width, "1.5")
    extra_classes = Keyword.get(opts, :extra_classes, "")

    """
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="#{stroke_width}"
      aria-hidden="true"
      class="#{size} #{color} #{extra_classes}"
    >
      <path
        stroke-linecap="round"
        stroke-linejoin="round"
        d="M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z"
      />
    </svg>
    """
  end

  @doc """
  Lightning bolt icon - for speed/performance features.

  ## Options

  - `:color` - Tailwind color class (default: "text-white")
  - `:size` - Size class (default: "size-6")
  - `:stroke_width` - SVG stroke width (default: "1.5")
  """
  def lightning(opts \\ []) do
    color = Keyword.get(opts, :color, "text-white")
    size = Keyword.get(opts, :size, "size-6")
    stroke_width = Keyword.get(opts, :stroke_width, "1.5")
    extra_classes = Keyword.get(opts, :extra_classes, "")

    """
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="#{stroke_width}"
      aria-hidden="true"
      class="#{size} #{color} #{extra_classes}"
    >
      <path
        stroke-linecap="round"
        stroke-linejoin="round"
        d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z"
      />
    </svg>
    """
  end

  @doc """
  Ascending chart icon - for growth/analytics features.

  ## Options

  - `:color` - Tailwind color class (default: "text-white")
  - `:size` - Size class (default: "size-6")
  - `:stroke_width` - SVG stroke width (default: "1.5")
  """
  def chart_up(opts \\ []) do
    color = Keyword.get(opts, :color, "text-white")
    size = Keyword.get(opts, :size, "size-6")
    stroke_width = Keyword.get(opts, :stroke_width, "1.5")
    extra_classes = Keyword.get(opts, :extra_classes, "")

    """
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="#{stroke_width}"
      aria-hidden="true"
      class="#{size} #{color} #{extra_classes}"
    >
      <path
        stroke-linecap="round"
        stroke-linejoin="round"
        d="M2.25 18 9 11.25l4.306 4.306a11.95 11.95 0 0 1 5.814-5.518l2.74-1.22m0 0-5.94-2.281m5.94 2.28-2.28 5.941"
      />
    </svg>
    """
  end

  @doc """
  Shield icon - for security features.

  ## Options

  - `:color` - Tailwind color class (default: "text-white")
  - `:size` - Size class (default: "size-6")
  - `:stroke_width` - SVG stroke width (default: "1.5")
  """
  def shield(opts \\ []) do
    color = Keyword.get(opts, :color, "text-white")
    size = Keyword.get(opts, :size, "size-6")
    stroke_width = Keyword.get(opts, :stroke_width, "1.5")
    extra_classes = Keyword.get(opts, :extra_classes, "")

    """
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="#{stroke_width}"
      aria-hidden="true"
      class="#{size} #{color} #{extra_classes}"
    >
      <path
        stroke-linecap="round"
        stroke-linejoin="round"
        d="M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z"
      />
    </svg>
    """
  end

  @doc """
  Code brackets icon - for development features.

  ## Options

  - `:color` - Tailwind color class (default: "text-white")
  - `:size` - Size class (default: "size-6")
  - `:stroke_width` - SVG stroke width (default: "1.5")
  """
  def code(opts \\ []) do
    color = Keyword.get(opts, :color, "text-white")
    size = Keyword.get(opts, :size, "size-6")
    stroke_width = Keyword.get(opts, :stroke_width, "1.5")
    extra_classes = Keyword.get(opts, :extra_classes, "")

    """
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="#{stroke_width}"
      aria-hidden="true"
      class="#{size} #{color} #{extra_classes}"
    >
      <path
        stroke-linecap="round"
        stroke-linejoin="round"
        d="M17.25 6.75 22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3-4.5 16.5"
      />
    </svg>
    """
  end

  @doc """
  Rocket icon - for launch/deployment features.

  ## Options

  - `:color` - Tailwind color class (default: "text-white")
  - `:size` - Size class (default: "size-6")
  - `:stroke_width` - SVG stroke width (default: "1.5")
  """
  def rocket(opts \\ []) do
    color = Keyword.get(opts, :color, "text-white")
    size = Keyword.get(opts, :size, "size-6")
    stroke_width = Keyword.get(opts, :stroke_width, "1.5")
    extra_classes = Keyword.get(opts, :extra_classes, "")

    """
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="#{stroke_width}"
      aria-hidden="true"
      class="#{size} #{color} #{extra_classes}"
    >
      <path
        stroke-linecap="round"
        stroke-linejoin="round"
        d="M15.59 14.37a6 6 0 0 1-5.84 7.38v-4.8m5.84-2.58a14.98 14.98 0 0 0 6.16-12.12A14.98 14.98 0 0 0 9.631 8.41m5.96 5.96a14.926 14.926 0 0 1-5.841 2.58m-.119-8.54a6 6 0 0 0-7.381 5.84h4.8m2.581-5.84a14.927 14.927 0 0 0-2.58 5.84m2.699 2.7c-.103.021-.207.041-.311.06a15.09 15.09 0 0 1-2.448-2.448 14.9 14.9 0 0 1 .06-.312m-2.24 2.39a4.493 4.493 0 0 0-1.757 4.306 4.493 4.493 0 0 0 4.306-1.758M16.5 9a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0Z"
      />
    </svg>
    """
  end
end
