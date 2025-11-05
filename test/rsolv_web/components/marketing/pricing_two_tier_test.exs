defmodule RsolvWeb.Components.Marketing.PricingTwoTierTest do
  use RsolvWeb.ConnCase, async: true
  import Phoenix.LiveViewTest

  alias RsolvWeb.Components.Marketing.PricingTwoTier

  @sample_tiers [
    %{
      name: "Starter",
      id: "tier-starter",
      price: "$0",
      period: "/month",
      description: "Perfect for individuals",
      features: ["10 credits", "Email support", "Basic analytics"],
      cta_text: "Get Started",
      cta_link: "/signup",
      highlighted: false
    },
    %{
      name: "Pro",
      id: "tier-pro",
      price: "$599",
      period: "/month",
      description: "For professional teams",
      features: [
        "60 fixes per month",
        "Priority support",
        "Advanced analytics",
        "Custom integrations"
      ],
      cta_text: "Start Pro",
      cta_link: "/signup?plan=pro",
      highlighted: true
    }
  ]

  describe "pricing_two_tier/1" do
    test "renders with required attributes" do
      assigns = %{
        heading: "Choose Your Plan",
        description: "Select the perfect plan for your needs",
        tiers: @sample_tiers
      }

      html = render_component(&PricingTwoTier.pricing_two_tier/1, assigns)

      assert html =~ "Choose Your Plan"
      assert html =~ "Select the perfect plan for your needs"
    end

    test "renders optional eyebrow text" do
      assigns = %{
        eyebrow: "Pricing",
        heading: "Choose Your Plan",
        description: "Plans for everyone",
        tiers: @sample_tiers
      }

      html = render_component(&PricingTwoTier.pricing_two_tier/1, assigns)

      assert html =~ "Pricing"
    end

    test "renders both tiers with correct styling" do
      assigns = %{
        heading: "Plans",
        description: "Test",
        tiers: @sample_tiers
      }

      html = render_component(&PricingTwoTier.pricing_two_tier/1, assigns)

      # Standard tier
      assert html =~ "Starter"
      assert html =~ "$0"
      assert html =~ "Perfect for individuals"

      # Highlighted tier
      assert html =~ "Pro"
      assert html =~ "$599"
      assert html =~ "For professional teams"
    end

    test "highlighted tier has dark background" do
      assigns = %{
        heading: "Plans",
        description: "Test",
        tiers: @sample_tiers
      }

      html = render_component(&PricingTwoTier.pricing_two_tier/1, assigns)

      # Dark background for highlighted tier
      assert html =~ "bg-gray-900"
      assert html =~ "shadow-2xl"
    end

    test "standard tier has light background" do
      assigns = %{
        heading: "Plans",
        description: "Test",
        tiers: @sample_tiers
      }

      html = render_component(&PricingTwoTier.pricing_two_tier/1, assigns)

      # Light background for standard tier
      assert html =~ "bg-white/60"
      assert html =~ "dark:bg-gray-800/60"
    end

    test "renders all features for each tier" do
      assigns = %{
        heading: "Plans",
        description: "Test",
        tiers: @sample_tiers
      }

      html = render_component(&PricingTwoTier.pricing_two_tier/1, assigns)

      # Starter features
      assert html =~ "10 credits"
      assert html =~ "Email support"
      assert html =~ "Basic analytics"

      # Pro features
      assert html =~ "60 fixes per month"
      assert html =~ "Priority support"
      assert html =~ "Advanced analytics"
      assert html =~ "Custom integrations"
    end

    test "features have checkmark icons" do
      assigns = %{
        heading: "Plans",
        description: "Test",
        tiers: @sample_tiers
      }

      html = render_component(&PricingTwoTier.pricing_two_tier/1, assigns)

      # SVG checkmark icon
      assert html =~ "<svg"
      assert html =~ "viewBox=\"0 0 20 20\""
      assert html =~ "M16.704 4.153"
    end

    test "each tier has proper CTA button" do
      assigns = %{
        heading: "Plans",
        description: "Test",
        tiers: @sample_tiers
      }

      html = render_component(&PricingTwoTier.pricing_two_tier/1, assigns)

      # Standard tier CTA
      assert html =~ "Get Started"
      assert html =~ "href=\"/signup\""

      # Highlighted tier CTA
      assert html =~ "Start Pro"
      assert html =~ "href=\"/signup?plan=pro\""
    end

    test "highlighted tier CTA has distinct styling" do
      assigns = %{
        heading: "Plans",
        description: "Test",
        tiers: @sample_tiers
      }

      html = render_component(&PricingTwoTier.pricing_two_tier/1, assigns)

      # Highlighted tier should have blue background button
      assert html =~ "bg-blue-500"
      assert html =~ "text-white"
    end

    test "standard tier CTA has ring style" do
      assigns = %{
        heading: "Plans",
        description: "Test",
        tiers: @sample_tiers
      }

      html = render_component(&PricingTwoTier.pricing_two_tier/1, assigns)

      # Standard tier should have ring/outline style
      assert html =~ "ring-1 ring-inset"
    end

    test "includes gradient decoration" do
      assigns = %{
        heading: "Plans",
        description: "Test",
        tiers: @sample_tiers
      }

      html = render_component(&PricingTwoTier.pricing_two_tier/1, assigns)

      assert html =~ "bg-gradient-to-tr from-blue-500 to-emerald-500"
      assert html =~ "blur-3xl"
      assert html =~ "clip-path"
    end

    test "uses aria-describedby for accessibility" do
      assigns = %{
        heading: "Plans",
        description: "Test",
        tiers: @sample_tiers
      }

      html = render_component(&PricingTwoTier.pricing_two_tier/1, assigns)

      assert html =~ "aria-describedby=\"tier-starter\""
      assert html =~ "aria-describedby=\"tier-pro\""
    end

    test "uses semantic HTML with role=list for features" do
      assigns = %{
        heading: "Plans",
        description: "Test",
        tiers: @sample_tiers
      }

      html = render_component(&PricingTwoTier.pricing_two_tier/1, assigns)

      assert html =~ "role=\"list\""
      assert html =~ "<ul"
    end

    test "has responsive grid layout" do
      assigns = %{
        heading: "Plans",
        description: "Test",
        tiers: @sample_tiers
      }

      html = render_component(&PricingTwoTier.pricing_two_tier/1, assigns)

      assert html =~ "grid"
      assert html =~ "grid-cols-1"
      assert html =~ "lg:grid-cols-2"
      assert html =~ "gap-y-6"
    end

    test "includes dark mode classes throughout" do
      assigns = %{
        heading: "Plans",
        description: "Test",
        tiers: @sample_tiers
      }

      html = render_component(&PricingTwoTier.pricing_two_tier/1, assigns)

      assert html =~ "dark:bg-gray-900"
      assert html =~ "dark:text-white"
      assert html =~ "dark:text-gray-400"
      assert html =~ "dark:text-blue-400"
    end

    test "applies custom CSS class" do
      assigns = %{
        heading: "Plans",
        description: "Test",
        tiers: @sample_tiers,
        class: "custom-pricing-class"
      }

      html = render_component(&PricingTwoTier.pricing_two_tier/1, assigns)

      assert html =~ "custom-pricing-class"
    end

    test "handles single tier" do
      assigns = %{
        heading: "Plans",
        description: "Test",
        tiers: [List.first(@sample_tiers)]
      }

      html = render_component(&PricingTwoTier.pricing_two_tier/1, assigns)

      assert html =~ "Starter"
      refute html =~ "Pro"
    end

    test "handles more than two tiers" do
      enterprise_tier = %{
        name: "Enterprise",
        id: "tier-enterprise",
        price: "Custom",
        period: "",
        description: "For large organizations",
        features: ["Unlimited fixes", "24/7 support", "SLA"],
        cta_text: "Contact Sales",
        cta_link: "/contact",
        highlighted: false
      }

      assigns = %{
        heading: "Plans",
        description: "Test",
        tiers: @sample_tiers ++ [enterprise_tier]
      }

      html = render_component(&PricingTwoTier.pricing_two_tier/1, assigns)

      assert html =~ "Starter"
      assert html =~ "Pro"
      assert html =~ "Enterprise"
    end

    test "tier IDs are used for aria-describedby linking" do
      assigns = %{
        heading: "Plans",
        description: "Test",
        tiers: @sample_tiers
      }

      html = render_component(&PricingTwoTier.pricing_two_tier/1, assigns)

      # Each CTA should reference its tier's ID
      assert html =~ "id=\"tier-starter\""
      assert html =~ "id=\"tier-pro\""
    end

    test "tier prices are prominently displayed" do
      assigns = %{
        heading: "Plans",
        description: "Test",
        tiers: @sample_tiers
      }

      html = render_component(&PricingTwoTier.pricing_two_tier/1, assigns)

      # Large text for prices
      assert html =~ "text-5xl font-semibold"
      assert html =~ "$0"
      assert html =~ "$599"
    end

    test "includes focus-visible styles for accessibility" do
      assigns = %{
        heading: "Plans",
        description: "Test",
        tiers: @sample_tiers
      }

      html = render_component(&PricingTwoTier.pricing_two_tier/1, assigns)

      assert html =~ "focus-visible:outline"
      assert html =~ "focus-visible:outline-2"
    end
  end
end
