defmodule RsolvWeb.PricingLive do
  @moduledoc """
  Pricing page LiveView for RFC-078 public site.

  Protected by the :public_site feature flag.

  Displays transparent pricing with three tiers from RFC-066:
  - Free: 10 free credits (5 on signup + 5 when adding payment method)
  - Pro: $599/month, 60 credits/month, $15/additional fix
  - Enterprise: Custom pricing
  """
  use RsolvWeb, :live_view

  import RsolvWeb.Live.Concerns.PageTracking

  alias Rsolv.PricingData
  alias RsolvWeb.Components.Marketing.{FaqSection, PricingTwoTier}

  @impl true
  def mount(params, _session, socket) do
    # Feature flag check handled by router pipeline
    socket =
      socket
      |> assign(:page_title, "Pricing")
      |> track_page_view(params, "/pricing")

    {:ok, socket}
  end

  @impl true
  def handle_event("track_cta_click", %{"destination" => destination, "plan" => plan}, socket) do
    track_cta_click(socket, destination, %{plan: plan, cta_type: "pricing"})
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="min-h-screen bg-white dark:bg-gray-900">
      <!-- Pricing Tiers -->
      <PricingTwoTier.pricing_two_tier
        eyebrow="Pricing"
        heading="Choose the right plan for you"
        description="Start with 10 free credits. Upgrade to Pro or contact us for Enterprise pricing."
        tiers={PricingData.tiers()}
      />
      
    <!-- FAQ Section -->
      <FaqSection.faq_section
        faqs={PricingData.faqs()}
        cta_text="Contact Us"
        cta_link="/contact"
      />
    </div>
    """
  end
end
