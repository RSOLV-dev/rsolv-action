defmodule RsolvWeb.Components.Marketing.FeaturesGrid2x2 do
  @moduledoc """
  Centered 2x2 grid feature section - adapted from Tailwind Plus.

  This component provides a professional features section with:
  - Centered section heading with eyebrow text
  - Subheading text
  - 2x2 grid of features (responsive: 1 column on mobile, 2 on desktop)
  - Each feature has an icon, title, and description
  - Dark background with indigo accent colors

  ## Examples

      <.features_grid_2x2
        eyebrow="Why RSOLV?"
        heading="Automated Security at Scale"
        subheading="AI-powered vulnerability detection and remediation for your entire codebase."
        features={[
          %{
            icon: ~S'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" stroke-linecap="round" stroke-linejoin="round" /></svg>',
            title: "Real Vulnerabilities",
            description: "Not false positives - only actionable security issues validated by AST analysis."
          },
          %{
            icon: ~S'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z" stroke-linecap="round" stroke-linejoin="round" /></svg>',
            title: "Verified Fixes",
            description: "Every fix is tested to ensure it resolves the vulnerability without breaking functionality."
          },
          %{
            icon: ~S'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" stroke-linecap="round" stroke-linejoin="round" /></svg>',
            title: "Lightning Fast",
            description: "Fixes generated and tested in minutes, not days. Get pull requests ready to merge."
          },
          %{
            icon: ~S'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M2.25 18 9 11.25l4.306 4.306a11.95 11.95 0 0 1 5.814-5.518l2.74-1.22m0 0-5.94-2.281m5.94 2.28-2.28 5.941" stroke-linecap="round" stroke-linejoin="round" /></svg>',
            title: "Continuous Security",
            description: "Automated scanning and fixing integrated into your development workflow."
          }
        ]}
      />
  """
  use Phoenix.Component

  @doc """
  Renders a centered 2x2 grid feature section.

  ## Attributes

  - `eyebrow` (optional) - Small heading above main heading
  - `heading` (required) - Main section heading
  - `subheading` (required) - Description text below heading
  - `features` (required) - List of feature maps with :icon, :title, :description
  - `class` - Additional CSS classes for the container
  """
  attr :eyebrow, :string, default: nil
  attr :heading, :string, required: true
  attr :subheading, :string, required: true
  attr :features, :list, required: true
  attr :class, :string, default: ""

  def features_grid_2x2(assigns) do
    ~H"""
    <div class={"bg-white dark:bg-gray-900 py-24 sm:py-32 #{@class}"}>
      <div class="mx-auto max-w-7xl px-6 lg:px-8">
        <div class="mx-auto max-w-2xl lg:text-center">
          <%= if @eyebrow do %>
            <h2 class="text-base/7 font-semibold text-blue-600 dark:text-blue-400">
              {@eyebrow}
            </h2>
          <% end %>
          <p class="mt-2 text-4xl font-semibold tracking-tight text-pretty text-gray-900 sm:text-5xl lg:text-balance dark:text-white">
            {@heading}
          </p>
          <p class="mt-6 text-lg/8 text-gray-600 dark:text-gray-300">
            {@subheading}
          </p>
        </div>
        <div class="mx-auto mt-16 max-w-2xl sm:mt-20 lg:mt-24 lg:max-w-4xl">
          <dl class="grid max-w-xl grid-cols-1 gap-x-8 gap-y-10 lg:max-w-none lg:grid-cols-2 lg:gap-y-16">
            <%= for feature <- @features do %>
              <div class="relative pl-16">
                <dt class="text-base/7 font-semibold text-gray-900 dark:text-white">
                  <div class="absolute top-0 left-0 flex size-10 items-center justify-center rounded-lg bg-blue-600 dark:bg-blue-500">
                    {Phoenix.HTML.raw(feature.icon)}
                  </div>
                  {feature.title}
                </dt>
                <dd class="mt-2 text-base/7 text-gray-600 dark:text-gray-400">
                  {feature.description}
                </dd>
              </div>
            <% end %>
          </dl>
        </div>
      </div>
    </div>
    """
  end
end
