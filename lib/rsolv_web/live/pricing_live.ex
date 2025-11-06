defmodule RsolvWeb.PricingLive do
  @moduledoc """
  Pricing page LiveView for RFC-078 public site.

  Protected by the :public_site feature flag.

  Displays transparent pricing with three tiers:
  - Free: 10 free credits (5 on signup + 5 when adding payment method)
  - Pro: $599/month, 60 credits/month, $15/additional fix
  - Enterprise: Custom pricing

  Pricing amounts from RFC-066-STRIPE-BILLING-INTEGRATION.md
  """
  use RsolvWeb, :live_view

  alias RsolvWeb.Components.Marketing.PricingTwoTier

  @impl true
  def mount(_params, _session, socket) do
    # Feature flag check handled by router pipeline
    {:ok, assign(socket, page_title: "Pricing")}
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
        tiers={pricing_tiers()}
      />

      <!-- FAQ Section -->
      <.faq_section />
    </div>
    """
  end

  # Pricing tier data from RFC-066
  defp pricing_tiers do
    [
      %{
        name: "Free Trial",
        id: "tier-free",
        price: "$0",
        period: "10 free credits",
        description: "Perfect for trying RSOLV on your first repositories. Get 5 credits on signup, plus 5 more when you add a payment method.",
        features: [
          "10 vulnerability fixes",
          "All security frameworks",
          "GitHub Actions integration",
          "Email support",
          "No credit card required"
        ],
        cta_text: "Start Free Trial",
        cta_link: "/signup",
        highlighted: false
      },
      %{
        name: "Pro",
        id: "tier-pro",
        price: "$599",
        period: "/month",
        description: "Best value for teams fixing vulnerabilities at scale. Includes 60 fixes per month with discounted overage.",
        features: [
          "60 vulnerability fixes per month",
          "Additional fixes at $15 each",
          "Priority AI processing",
          "Advanced analytics dashboard",
          "Dedicated support",
          "Custom integrations",
          "SLA guarantee"
        ],
        cta_text: "Start Pro Trial",
        cta_link: "/signup?plan=pro",
        highlighted: true
      },
      %{
        name: "Enterprise",
        id: "tier-enterprise",
        price: "Custom",
        period: "pricing",
        description: "For organizations requiring custom solutions, dedicated support, and compliance features.",
        features: [
          "Unlimited fixes",
          "Self-hosted options",
          "SOC 2 / ISO 27001 compliance",
          "Custom SLAs",
          "Dedicated account manager",
          "Training & onboarding",
          "Custom integrations"
        ],
        cta_text: "Contact Sales",
        cta_link: "/contact",
        highlighted: false
      }
    ]
  end

  # FAQ Section Component
  defp faq_section(assigns) do
    ~H"""
    <div class="bg-gray-50 dark:bg-gray-800 px-6 py-24 sm:py-32 lg:px-8">
      <div class="mx-auto max-w-4xl">
        <h2 class="text-4xl font-semibold tracking-tight text-gray-900 dark:text-white text-center mb-16">
          Frequently Asked Questions
        </h2>

        <dl class="space-y-8">
          <.faq_item
            question="What counts as a 'fix'?"
            answer="A fix is one complete vulnerability remediation - from detection through validation and deployment. Each successful pull request created by RSOLV counts as one fix, regardless of how many lines of code are changed."
          />

          <.faq_item
            question="When does billing start?"
            answer="You get 10 free credits to start (5 on signup + 5 when adding a payment method). After using your free credits, you'll be charged based on your plan: $29 per fix for pay-as-you-go customers, or $15 per additional fix beyond 60 for Pro subscribers."
          />

          <.faq_item
            question="How do credits work?"
            answer="Credits are consumed when RSOLV successfully deploys a vulnerability fix. You start with 10 free credits. Pro subscribers receive 60 credits each month. When you run out of credits, additional fixes are charged automatically based on your plan."
          />

          <.faq_item
            question="What if I exceed 60 fixes on the Pro plan?"
            answer="Additional fixes beyond your monthly 60 are charged at a discounted rate of $15 per fix (compared to $29 for pay-as-you-go). There's no limit - we'll automatically charge for additional fixes as needed."
          />

          <.faq_item
            question="Can I cancel anytime?"
            answer="Yes! You can cancel your Pro subscription at any time. You can choose to cancel immediately or at the end of your current billing period. Any remaining credits will be preserved and can be used after cancellation at the pay-as-you-go rate."
          />

          <.faq_item
            question="Do you offer refunds?"
            answer="We're committed to your satisfaction. Contact our support team within 30 days of your initial Pro subscription payment for a full refund if RSOLV doesn't meet your expectations."
          />

          <.faq_item
            question="What payment methods do you accept?"
            answer="We accept all major credit cards (Visa, Mastercard, American Express, Discover) through our secure payment processor, Stripe. All payment information is encrypted and we never store your card details."
          />

          <.faq_item
            question="Is there a setup fee?"
            answer="No setup fees! You can start using RSOLV immediately with your free credits. There are no hidden charges - you only pay for successful vulnerability fixes."
          />

          <.faq_item
            question="Can I upgrade or downgrade my plan?"
            answer="Yes! You can upgrade to Pro at any time to get better per-fix pricing. If you cancel your Pro subscription, you'll automatically move to pay-as-you-go pricing for any additional fixes."
          />

          <.faq_item
            question="What happens to unused credits?"
            answer="Free trial credits never expire. Pro plan credits are refreshed monthly and don't roll over. If you cancel your Pro subscription, any remaining credits from your free trial are preserved."
          />
        </dl>

        <!-- CTA at bottom of FAQ -->
        <div class="mt-16 text-center">
          <p class="text-lg text-gray-600 dark:text-gray-400 mb-6">
            Still have questions?
          </p>
          <a
            href="/contact"
            class="inline-flex items-center justify-center rounded-md bg-blue-600 px-6 py-3 text-base font-semibold text-white shadow-sm hover:bg-blue-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 dark:bg-blue-500 dark:hover:bg-blue-400"
          >
            Contact Us
          </a>
        </div>
      </div>
    </div>
    """
  end

  # FAQ Item Component
  attr :question, :string, required: true
  attr :answer, :string, required: true

  defp faq_item(assigns) do
    ~H"""
    <div>
      <dt class="text-lg font-semibold text-gray-900 dark:text-white mb-2">
        {@question}
      </dt>
      <dd class="text-base text-gray-600 dark:text-gray-400">
        {@answer}
      </dd>
    </div>
    """
  end
end
