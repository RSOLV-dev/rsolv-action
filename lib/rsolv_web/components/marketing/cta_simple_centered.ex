defmodule RsolvWeb.Components.Marketing.CtaSimpleCentered do
  @moduledoc """
  Simple centered CTA section - adapted from Tailwind Plus.

  This component provides a professional call-to-action section with:
  - Gradient background decoration
  - Centered or left-aligned content
  - Heading and description text
  - Primary and secondary CTA buttons
  - Optional app screenshot/image
  - Responsive design with dark background

  ## Examples

      <.cta_simple_centered
        heading="See RSOLV in Action"
        description="Check out our demo repository with real vulnerability fixes."
        primary_cta_text="View Demo Repository"
        primary_cta_link="https://github.com/RSOLV-dev/nodegoat-vulnerability-demo"
        secondary_cta_text="Learn more"
        secondary_cta_link="/docs"
      />

      <.cta_simple_centered
        heading="Boost your productivity. Start using our app today."
        description="Ac euismod vel sit maecenas id pellentesque eu sed consectetur."
        primary_cta_text="Get started"
        primary_cta_link="/signup"
        secondary_cta_text="Learn more"
        secondary_cta_link="/docs"
        image_url="https://example.com/screenshot.png"
        image_alt="App screenshot"
      />
  """
  use Phoenix.Component

  @doc """
  Renders a simple centered CTA section with gradient decoration.

  ## Attributes

  - `heading` (required) - Main CTA heading
  - `description` (required) - Description text
  - `primary_cta_text` (required) - Text for primary CTA button
  - `primary_cta_link` (required) - Link for primary CTA
  - `secondary_cta_text` (optional) - Text for secondary CTA link
  - `secondary_cta_link` (optional) - Link for secondary CTA
  - `image_url` (optional) - URL for app screenshot/image
  - `image_alt` (optional) - Alt text for image
  - `class` - Additional CSS classes for the container
  """
  attr :heading, :string, required: true
  attr :description, :string, required: true
  attr :primary_cta_text, :string, required: true
  attr :primary_cta_link, :string, required: true
  attr :secondary_cta_text, :string, default: nil
  attr :secondary_cta_link, :string, default: nil
  attr :image_url, :string, default: nil
  attr :image_alt, :string, default: "App screenshot"
  attr :class, :string, default: ""

  def cta_simple_centered(assigns) do
    ~H"""
    <div class={"bg-white dark:bg-gray-900 #{@class}"}>
      <div class="mx-auto max-w-7xl py-24 sm:px-6 sm:py-32 lg:px-8">
        <div class="relative isolate overflow-hidden bg-gray-900 px-6 pt-16 shadow-2xl sm:rounded-3xl sm:px-16 md:pt-24 lg:flex lg:gap-x-20 lg:px-24 lg:pt-0">
          <!-- Gradient decoration -->
          <svg
            viewBox="0 0 1024 1024"
            aria-hidden="true"
            class="absolute top-1/2 left-1/2 -z-10 size-256 -translate-y-1/2 [mask-image:radial-gradient(closest-side,white,transparent)] sm:left-full sm:-ml-80 lg:left-1/2 lg:ml-0 lg:-translate-x-1/2 lg:translate-y-0"
          >
            <circle
              r="512"
              cx="512"
              cy="512"
              fill="url(#gradient-cta)"
              fill-opacity="0.7"
            >
            </circle>
            <defs>
              <radialGradient id="gradient-cta">
                <stop stop-color="#3B82F6"></stop>
                <stop offset="1" stop-color="#10B981"></stop>
              </radialGradient>
            </defs>
          </svg>

          <!-- Content -->
          <div class={"mx-auto max-w-md text-center lg:mx-0 lg:flex-auto lg:py-32 #{if @image_url, do: "lg:text-left", else: ""}"}>
            <h2 class="text-3xl font-semibold tracking-tight text-balance text-white sm:text-4xl">
              {@heading}
            </h2>
            <p class="mt-6 text-lg/8 text-pretty text-gray-300">
              {@description}
            </p>
            <div class={"mt-10 flex items-center gap-x-6 #{if @image_url, do: "justify-center lg:justify-start", else: "justify-center"}"}>
              <a
                href={@primary_cta_link}
                class="rounded-md bg-white px-3.5 py-2.5 text-sm font-semibold text-gray-900 shadow-xs hover:bg-gray-100 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-white"
              >
                {@primary_cta_text}
              </a>
              <%= if @secondary_cta_text && @secondary_cta_link do %>
                <a
                  href={@secondary_cta_link}
                  class="text-sm/6 font-semibold text-white hover:text-gray-100"
                >
                  {@secondary_cta_text}
                  <span aria-hidden="true">→</span>
                </a>
              <% end %>
            </div>
          </div>

          <!-- Optional image -->
          <%= if @image_url do %>
            <div class="relative mt-16 h-80 lg:mt-8">
              <img
                width="1824"
                height="1080"
                src={@image_url}
                alt={@image_alt}
                class="absolute top-0 left-0 w-228 max-w-none rounded-md bg-white/5 ring-1 ring-white/10"
              />
            </div>
          <% end %>
        </div>
      </div>
    </div>
    """
  end
end
