defmodule RsolvWeb.Components.Marketing.PricingTwoTier do
  @moduledoc """
  Two-tier pricing section with emphasized right tier - adapted from Tailwind Plus.

  This component provides a professional pricing comparison with:
  - Gradient background decoration
  - Section heading and description
  - Two pricing tiers side by side
  - Left tier: Light background (standard plan)
  - Right tier: Dark background with emphasis (premium/enterprise plan)
  - Feature lists with checkmark icons
  - CTA buttons for each tier
  - Fully responsive design

  ## Examples

      <.pricing_two_tier
        eyebrow="Pricing"
        heading="Choose the right plan for you"
        description="Start with 10 free credits. Upgrade to Pro or pay as you go."
        tiers={[
          %{
            name: "Starter",
            id: "tier-starter",
            price: "$0",
            period: "10 free credits",
            description: "Perfect for trying RSOLV on your first repositories.",
            features: [
              "10 free vulnerability fixes",
              "All security frameworks",
              "GitHub integration",
              "Email support"
            ],
            cta_text: "Start Free",
            cta_link: "/signup",
            highlighted: false
          },
          %{
            name: "Pro",
            id: "tier-pro",
            price: "$599",
            period: "/month",
            description: "Best for teams fixing vulnerabilities at scale.",
            features: [
              "60 vulnerability fixes per month",
              "Priority AI processing",
              "Advanced analytics",
              "Dedicated support",
              "Custom integrations",
              "SLA guarantee"
            ],
            cta_text: "Start Pro Trial",
            cta_link: "/signup?plan=pro",
            highlighted: true
          }
        ]}
      />
  """
  use Phoenix.Component

  alias RsolvWeb.Components.Marketing.GradientDecoration
  alias RsolvWeb.Components.Marketing.Icons

  @doc """
  Renders a two-tier pricing section.

  ## Attributes

  - `eyebrow` (optional) - Small heading above main heading
  - `heading` (required) - Main section heading
  - `description` (required) - Description text below heading
  - `tiers` (required) - List of tier maps with keys: :name, :id, :price, :period, :description, :features (list), :cta_text, :cta_link, :highlighted (boolean)
  - `class` - Additional CSS classes for the container
  """
  attr :eyebrow, :string, default: "Pricing"
  attr :heading, :string, required: true
  attr :description, :string, required: true
  attr :tiers, :list, required: true
  attr :class, :string, default: ""

  def pricing_two_tier(assigns) do
    ~H"""
    <div class={"relative isolate bg-white dark:bg-gray-900 px-6 py-24 sm:py-32 lg:px-8 #{@class}"}>
      <!-- Gradient decoration -->
      <GradientDecoration.gradient_blur position={:top} from_color="blue-500" to_color="emerald-500" />
      <!-- Header -->
      <.section_header eyebrow={@eyebrow} heading={@heading} description={@description} />
      <!-- Pricing tiers -->
      <div class={get_grid_classes(length(@tiers))}>
        <%= for {tier, index} <- Enum.with_index(@tiers) do %>
          <.pricing_tier_card tier={tier} index={index} total_tiers={length(@tiers)} />
        <% end %>
      </div>
    </div>
    """
  end

  # Private helper functions

  defp get_grid_classes(2) do
    "mx-auto mt-16 grid max-w-lg grid-cols-1 items-center gap-y-6 sm:mt-20 sm:gap-y-0 lg:max-w-4xl lg:grid-cols-2"
  end

  defp get_grid_classes(3) do
    "mx-auto mt-16 grid max-w-lg grid-cols-1 items-stretch gap-6 sm:mt-20 lg:max-w-6xl lg:grid-cols-3"
  end

  defp get_grid_classes(_) do
    # Fallback for other counts
    "mx-auto mt-16 grid max-w-lg grid-cols-1 items-stretch gap-6 sm:mt-20 lg:max-w-6xl lg:grid-cols-2"
  end

  # Private function components

  attr :eyebrow, :string, required: true
  attr :heading, :string, required: true
  attr :description, :string, required: true

  defp section_header(assigns) do
    ~H"""
    <div class="mx-auto max-w-4xl text-center">
      <h2 class="text-base/7 font-semibold text-blue-600 dark:text-blue-400">
        {@eyebrow}
      </h2>
      <p class="mt-2 text-5xl font-semibold tracking-tight text-balance text-gray-900 sm:text-6xl dark:text-white">
        {@heading}
      </p>
    </div>
    <p class="mx-auto mt-6 max-w-2xl text-center text-lg font-medium text-pretty text-gray-600 sm:text-xl/8 dark:text-gray-400">
      {@description}
    </p>
    """
  end

  attr :tier, :map, required: true
  attr :index, :integer, required: true
  attr :total_tiers, :integer, required: true

  defp pricing_tier_card(assigns) do
    ~H"""
    <%= if @tier.highlighted do %>
      <.highlighted_tier tier={@tier} />
    <% else %>
      <.standard_tier tier={@tier} index={@index} total_tiers={@total_tiers} />
    <% end %>
    """
  end

  attr :tier, :map, required: true

  defp highlighted_tier(assigns) do
    ~H"""
    <div class="relative rounded-3xl bg-gray-900 p-8 shadow-2xl ring-1 ring-gray-900/10 sm:p-10">
      <h3 id={@tier.id} class="text-base/7 font-semibold text-blue-400">
        {@tier.name}
      </h3>
      <.tier_pricing price={@tier.price} period={@tier.period} highlighted={true} />
      <p class="mt-6 text-base/7 text-gray-300">{@tier.description}</p>
      <.feature_list features={@tier.features} highlighted={true} />
      <.tier_cta
        tier_id={@tier.id}
        cta_link={@tier.cta_link}
        cta_text={@tier.cta_text}
        highlighted={true}
      />
    </div>
    """
  end

  attr :tier, :map, required: true
  attr :index, :integer, required: true
  attr :total_tiers, :integer, required: true

  defp standard_tier(assigns) do
    # For 3-tier layouts, don't add special rounded corners
    # For 2-tier layouts, keep the original special styling for first tier
    rounded_classes =
      if assigns.total_tiers == 2 && assigns.index == 0 do
        "rounded-t-3xl sm:mx-8 sm:rounded-b-none lg:mx-0 lg:rounded-bl-3xl lg:rounded-tr-none"
      else
        ""
      end

    assigns = assign(assigns, :rounded_classes, rounded_classes)

    ~H"""
    <div class={"rounded-3xl bg-white/60 dark:bg-gray-800/60 p-8 ring-1 ring-gray-900/10 dark:ring-white/10 sm:p-10 #{@rounded_classes}"}>
      <h3 id={@tier.id} class="text-base/7 font-semibold text-blue-600 dark:text-blue-400">
        {@tier.name}
      </h3>
      <.tier_pricing price={@tier.price} period={@tier.period} highlighted={false} />
      <p class="mt-6 text-base/7 text-gray-600 dark:text-gray-400">{@tier.description}</p>
      <.feature_list features={@tier.features} highlighted={false} />
      <.tier_cta
        tier_id={@tier.id}
        cta_link={@tier.cta_link}
        cta_text={@tier.cta_text}
        highlighted={false}
      />
    </div>
    """
  end

  attr :price, :string, required: true
  attr :period, :string, required: true
  attr :highlighted, :boolean, required: true

  defp tier_pricing(assigns) do
    ~H"""
    <p class="mt-4 flex items-baseline gap-x-2">
      <span class={"text-5xl font-semibold tracking-tight #{if @highlighted, do: "text-white", else: "text-gray-900 dark:text-white"}"}>
        {@price}
      </span>
      <span class={"text-base #{if @highlighted, do: "text-gray-400", else: "text-gray-500 dark:text-gray-400"}"}>
        {@period}
      </span>
    </p>
    """
  end

  attr :features, :list, required: true
  attr :highlighted, :boolean, required: true

  defp feature_list(assigns) do
    ~H"""
    <ul
      role="list"
      class={"mt-8 space-y-3 text-sm/6 sm:mt-10 #{if @highlighted, do: "text-gray-300", else: "text-gray-600 dark:text-gray-400"}"}
    >
      <%= for feature <- @features do %>
        <li class="flex gap-x-3">
          {Phoenix.HTML.raw(
            Icons.checkmark(
              color: if(@highlighted, do: "text-blue-400", else: "text-blue-600 dark:text-blue-400")
            )
          )}
          {feature}
        </li>
      <% end %>
    </ul>
    """
  end

  attr :tier_id, :string, required: true
  attr :cta_link, :string, required: true
  attr :cta_text, :string, required: true
  attr :highlighted, :boolean, required: true

  defp tier_cta(assigns) do
    ~H"""
    <%= if @highlighted do %>
      <a
        href={@cta_link}
        aria-describedby={@tier_id}
        class="mt-8 block rounded-md bg-blue-500 px-3.5 py-2.5 text-center text-sm font-semibold text-white shadow-xs hover:bg-blue-400 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-500 sm:mt-10"
      >
        {@cta_text}
      </a>
    <% else %>
      <a
        href={@cta_link}
        aria-describedby={@tier_id}
        class="mt-8 block rounded-md px-3.5 py-2.5 text-center text-sm font-semibold text-blue-600 dark:text-blue-400 ring-1 ring-inset ring-blue-200 dark:ring-blue-800 hover:ring-blue-300 dark:hover:ring-blue-700 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 dark:focus-visible:outline-blue-400 sm:mt-10"
      >
        {@cta_text}
      </a>
    <% end %>
    """
  end
end
