defmodule Rsolv.PricingData do
  @moduledoc """
  Centralized pricing and plan data for RSOLV.

  This module provides:
  - Pricing tier definitions (Free, Pro, Enterprise)
  - Pricing amounts from RFC-066
  - FAQ content for pricing page

  Used by:
  - PricingLive (public pricing page)
  - Future: Customer portal, emails, API responses
  """

  @doc """
  Returns all pricing tiers with features, pricing, and CTAs.

  Pricing amounts from RFC-066-STRIPE-BILLING-INTEGRATION.md:
  - Free: 10 credits (5 on signup + 5 when adding payment method)
  - Pro: $599/month, 60 fixes/month, $15/additional fix
  - Enterprise: Custom pricing

  ## Examples

      iex> Rsolv.PricingData.tiers()
      [%{name: "Free Trial", price: "$0", ...}, ...]
  """
  def tiers do
    [
      %{
        name: "Free Trial",
        id: "tier-free",
        price: "$0",
        period: "10 free credits",
        description:
          "Perfect for trying RSOLV on your first repositories. Get 5 credits on signup, plus 5 more when you add a payment method.",
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
        description:
          "Best value for teams fixing vulnerabilities at scale. Includes 60 fixes per month with discounted overage.",
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
        description:
          "For organizations requiring custom solutions, dedicated support, and compliance features.",
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

  @doc """
  Returns pricing FAQ content.

  ## Examples

      iex> Rsolv.PricingData.faqs()
      [%{question: "What counts as a 'fix'?", answer: "..."}, ...]
  """
  def faqs do
    [
      %{
        question: "What counts as a 'fix'?",
        answer:
          "A fix is one complete vulnerability remediation - from detection through validation and deployment. Each successful pull request created by RSOLV counts as one fix, regardless of how many lines of code are changed."
      },
      %{
        question: "When does billing start?",
        answer:
          "You get 10 free credits to start (5 on signup + 5 when adding a payment method). After using your free credits, you'll be charged based on your plan: $29 per fix for pay-as-you-go customers, or $15 per additional fix beyond 60 for Pro subscribers."
      },
      %{
        question: "How do credits work?",
        answer:
          "Credits are consumed when RSOLV successfully deploys a vulnerability fix. You start with 10 free credits. Pro subscribers receive 60 credits each month. When you run out of credits, additional fixes are charged automatically based on your plan."
      },
      %{
        question: "What if I exceed 60 fixes on the Pro plan?",
        answer:
          "Additional fixes beyond your monthly 60 are charged at a discounted rate of $15 per fix (compared to $29 for pay-as-you-go). There's no limit - we'll automatically charge for additional fixes as needed."
      },
      %{
        question: "Can I cancel anytime?",
        answer:
          "Yes! You can cancel your Pro subscription at any time. You can choose to cancel immediately or at the end of your current billing period. Any remaining credits will be preserved and can be used after cancellation at the pay-as-you-go rate."
      },
      %{
        question: "Do you offer refunds?",
        answer:
          "We're committed to your satisfaction. Contact our support team within 30 days of your initial Pro subscription payment for a full refund if RSOLV doesn't meet your expectations."
      },
      %{
        question: "What payment methods do you accept?",
        answer:
          "We accept all major credit cards (Visa, Mastercard, American Express, Discover) through our secure payment processor, Stripe. All payment information is encrypted and we never store your card details."
      },
      %{
        question: "Is there a setup fee?",
        answer:
          "No setup fees! You can start using RSOLV immediately with your free credits. There are no hidden charges - you only pay for successful vulnerability fixes."
      },
      %{
        question: "Can I upgrade or downgrade my plan?",
        answer:
          "Yes! You can upgrade to Pro at any time to get better per-fix pricing. If you cancel your Pro subscription, you'll automatically move to pay-as-you-go pricing for any additional fixes."
      },
      %{
        question: "What happens to unused credits?",
        answer:
          "Free trial credits never expire. Pro plan credits are refreshed monthly and don't roll over. If you cancel your Pro subscription, any remaining credits from your free trial are preserved."
      }
    ]
  end
end
