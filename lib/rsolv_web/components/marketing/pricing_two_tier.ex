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
      <div
        aria-hidden="true"
        class="absolute inset-x-0 -top-3 -z-10 transform-gpu overflow-hidden px-36 blur-3xl"
      >
        <div
          style="clip-path: polygon(74.1% 44.1%, 100% 61.6%, 97.5% 26.9%, 85.5% 0.1%, 80.7% 2%, 72.5% 32.5%, 60.2% 62.4%, 52.4% 68.1%, 47.5% 58.3%, 45.2% 34.5%, 27.5% 76.7%, 0.1% 64.9%, 17.9% 100%, 27.6% 76.8%, 76.1% 97.7%, 74.1% 44.1%)"
          class="mx-auto aspect-[1155/678] w-[288.75rem] bg-gradient-to-tr from-blue-500 to-emerald-500 opacity-30"
        >
        </div>
      </div>

      <!-- Header -->
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

      <!-- Pricing tiers -->
      <div class="mx-auto mt-16 grid max-w-lg grid-cols-1 items-center gap-y-6 sm:mt-20 sm:gap-y-0 lg:max-w-4xl lg:grid-cols-2">
        <%= for {tier, index} <- Enum.with_index(@tiers) do %>
          <%= if tier.highlighted do %>
            <!-- Highlighted tier (dark) -->
            <div class="relative rounded-3xl bg-gray-900 p-8 shadow-2xl ring-1 ring-gray-900/10 sm:p-10">
              <h3 id={tier.id} class="text-base/7 font-semibold text-blue-400">
                {tier.name}
              </h3>
              <p class="mt-4 flex items-baseline gap-x-2">
                <span class="text-5xl font-semibold tracking-tight text-white">
                  {tier.price}
                </span>
                <span class="text-base text-gray-400">{tier.period}</span>
              </p>
              <p class="mt-6 text-base/7 text-gray-300">{tier.description}</p>
              <ul role="list" class="mt-8 space-y-3 text-sm/6 text-gray-300 sm:mt-10">
                <%= for feature <- tier.features do %>
                  <li class="flex gap-x-3">
                    <svg
                      viewBox="0 0 20 20"
                      fill="currentColor"
                      aria-hidden="true"
                      class="h-6 w-5 flex-none text-blue-400"
                    >
                      <path
                        d="M16.704 4.153a.75.75 0 0 1 .143 1.052l-8 10.5a.75.75 0 0 1-1.127.075l-4.5-4.5a.75.75 0 0 1 1.06-1.06l3.894 3.893 7.48-9.817a.75.75 0 0 1 1.05-.143Z"
                        clip-rule="evenodd"
                        fill-rule="evenodd"
                      />
                    </svg>
                    {feature}
                  </li>
                <% end %>
              </ul>
              <a
                href={tier.cta_link}
                aria-describedby={tier.id}
                class="mt-8 block rounded-md bg-blue-500 px-3.5 py-2.5 text-center text-sm font-semibold text-white shadow-xs hover:bg-blue-400 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-500 sm:mt-10"
              >
                {tier.cta_text}
              </a>
            </div>
          <% else %>
            <!-- Standard tier (light) -->
            <div class={"rounded-3xl bg-white/60 dark:bg-gray-800/60 p-8 ring-1 ring-gray-900/10 dark:ring-white/10 sm:p-10 #{if index == 0, do: "rounded-t-3xl sm:mx-8 sm:rounded-b-none lg:mx-0 lg:rounded-bl-3xl lg:rounded-tr-none", else: ""}"}>
              <h3 id={tier.id} class="text-base/7 font-semibold text-blue-600 dark:text-blue-400">
                {tier.name}
              </h3>
              <p class="mt-4 flex items-baseline gap-x-2">
                <span class="text-5xl font-semibold tracking-tight text-gray-900 dark:text-white">
                  {tier.price}
                </span>
                <span class="text-base text-gray-500 dark:text-gray-400">
                  {tier.period}
                </span>
              </p>
              <p class="mt-6 text-base/7 text-gray-600 dark:text-gray-400">
                {tier.description}
              </p>
              <ul role="list" class="mt-8 space-y-3 text-sm/6 text-gray-600 dark:text-gray-400 sm:mt-10">
                <%= for feature <- tier.features do %>
                  <li class="flex gap-x-3">
                    <svg
                      viewBox="0 0 20 20"
                      fill="currentColor"
                      aria-hidden="true"
                      class="h-6 w-5 flex-none text-blue-600 dark:text-blue-400"
                    >
                      <path
                        d="M16.704 4.153a.75.75 0 0 1 .143 1.052l-8 10.5a.75.75 0 0 1-1.127.075l-4.5-4.5a.75.75 0 0 1 1.06-1.06l3.894 3.893 7.48-9.817a.75.75 0 0 1 1.05-.143Z"
                        clip-rule="evenodd"
                        fill-rule="evenodd"
                      />
                    </svg>
                    {feature}
                  </li>
                <% end %>
              </ul>
              <a
                href={tier.cta_link}
                aria-describedby={tier.id}
                class="mt-8 block rounded-md px-3.5 py-2.5 text-center text-sm font-semibold text-blue-600 dark:text-blue-400 ring-1 ring-inset ring-blue-200 dark:ring-blue-800 hover:ring-blue-300 dark:hover:ring-blue-700 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 dark:focus-visible:outline-blue-400 sm:mt-10"
              >
                {tier.cta_text}
              </a>
            </div>
          <% end %>
        <% end %>
      </div>
    </div>
    """
  end
end
