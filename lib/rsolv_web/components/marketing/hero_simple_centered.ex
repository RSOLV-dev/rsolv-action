defmodule RsolvWeb.Components.Marketing.HeroSimpleCentered do
  @moduledoc """
  Simple centered hero section with gradient background - adapted from Tailwind Plus.

  This component provides a professional hero section with:
  - Decorative gradient background elements with blur effects
  - Announcement badge (optional)
  - Large centered heading
  - Subheading text
  - Primary and secondary CTA buttons
  - Fully responsive design

  ## Examples

      <.hero_simple_centered
        heading="Automated Security Fixes for Your Codebase"
        subheading="AI-powered vulnerability detection and remediation. Get 10 free credits to start."
        primary_cta_text="Start Free Trial"
        primary_cta_link="/signup"
        secondary_cta_text="Learn more"
        secondary_cta_link="/docs"
      />

      <.hero_simple_centered
        heading="Your Heading Here"
        subheading="Your description here"
        primary_cta_text="Get started"
        primary_cta_link="/signup"
        announcement_text="Announcing our next round of funding."
        announcement_link="/blog/funding"
        announcement_link_text="Read more"
      />
  """
  use Phoenix.Component

  alias RsolvWeb.Components.Marketing.GradientDecoration

  @doc """
  Renders a simple centered hero section with gradient background decorations.

  ## Attributes

  - `heading` (required) - Main hero heading text
  - `subheading` (required) - Subheading/description text
  - `primary_cta_text` (required) - Text for primary CTA button
  - `primary_cta_link` (required) - Link for primary CTA
  - `secondary_cta_text` - Text for secondary CTA link (optional)
  - `secondary_cta_link` - Link for secondary CTA (optional)
  - `announcement_text` - Text for announcement badge (optional)
  - `announcement_link` - Link for announcement (optional)
  - `announcement_link_text` - Link text within announcement (optional)
  - `class` - Additional CSS classes for the container
  """
  attr :heading, :string, required: true
  attr :subheading, :string, required: true
  attr :primary_cta_text, :string, required: true
  attr :primary_cta_link, :string, required: true
  attr :secondary_cta_text, :string, default: nil
  attr :secondary_cta_link, :string, default: nil
  attr :announcement_text, :string, default: nil
  attr :announcement_link, :string, default: nil
  attr :announcement_link_text, :string, default: nil
  attr :class, :string, default: ""

  def hero_simple_centered(assigns) do
    ~H"""
    <div class={"bg-white dark:bg-gray-900 #{@class}"}>
      <div class="relative isolate px-6 pt-14 lg:px-8">
        <!-- Top decorative gradient blur -->
        <GradientDecoration.gradient_blur position={:top} />

        <div class="mx-auto max-w-2xl py-32 sm:py-48 lg:py-56">
          <!-- Announcement badge (optional) -->
          <%= if @announcement_text do %>
            <div class="hidden sm:mb-8 sm:flex sm:justify-center">
              <div class="relative rounded-full px-3 py-1 text-sm/6 text-gray-600 ring-1 ring-gray-900/10 hover:ring-gray-900/20 dark:text-gray-400 dark:ring-white/10 dark:hover:ring-white/20">
                {@announcement_text}
                <%= if @announcement_link do %>
                  <a
                    href={@announcement_link}
                    class="font-semibold text-blue-600 dark:text-blue-400"
                  >
                    <span aria-hidden="true" class="absolute inset-0"></span>
                    {@announcement_link_text || "Read more"} <span aria-hidden="true">&rarr;</span>
                  </a>
                <% end %>
              </div>
            </div>
          <% end %>
          
    <!-- Hero content -->
          <div class="text-center">
            <h1 class="text-5xl font-semibold tracking-tight text-balance text-gray-900 sm:text-7xl dark:text-white">
              {@heading}
            </h1>
            <p class="mt-8 text-lg font-medium text-pretty text-gray-500 sm:text-xl/8 dark:text-gray-400">
              {@subheading}
            </p>
            
    <!-- CTA buttons -->
            <div class="mt-10 flex items-center justify-center gap-x-6">
              <a
                href={@primary_cta_link}
                class="rounded-md bg-blue-600 px-3.5 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-blue-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 dark:bg-blue-500 dark:hover:bg-blue-400 dark:focus-visible:outline-blue-500"
              >
                {@primary_cta_text}
              </a>
              <%= if @secondary_cta_text && @secondary_cta_link do %>
                <a
                  href={@secondary_cta_link}
                  class="text-sm/6 font-semibold text-gray-900 dark:text-white"
                >
                  {@secondary_cta_text} <span aria-hidden="true">→</span>
                </a>
              <% end %>
            </div>
          </div>
        </div>
        
    <!-- Bottom decorative gradient blur -->
        <GradientDecoration.gradient_blur position={:bottom} />
      </div>
    </div>
    """
  end
end
