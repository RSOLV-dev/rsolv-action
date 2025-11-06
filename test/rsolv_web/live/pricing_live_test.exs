defmodule RsolvWeb.PricingLiveTest do
  use RsolvWeb.ConnCase, async: false

  import Phoenix.LiveViewTest
  alias RsolvWeb.FunWithFlagsHelper

  setup do
    # ConnCase already checks out the sandbox, just set to shared mode
    # so FunWithFlags queries can access the same transaction
    Ecto.Adapters.SQL.Sandbox.mode(Rsolv.Repo, {:shared, self()})
    :ok
  end

  describe "pricing page with feature flag ON" do
    setup do
      # Enable feature flag for these tests using sandbox-safe helper
      FunWithFlagsHelper.enable_flag(:public_site)

      on_exit(fn ->
        FunWithFlagsHelper.disable_flag(:public_site)
      end)

      :ok
    end
    test "displays all three pricing tiers", %{conn: conn} do
      {:ok, view, html} = live(conn, ~p"/pricing")

      # Check all tiers are present
      assert html =~ "Free Trial"
      assert html =~ "Pro"
      assert html =~ "Enterprise"
    end

    test "shows correct pricing amounts from RFC-066", %{conn: conn} do
      {:ok, _view, html} = live(conn, ~p"/pricing")

      # Free tier
      assert html =~ "$0"
      assert html =~ "10 free credits"

      # Pro tier (from RFC-066)
      assert html =~ "$599"
      assert html =~ "/month"
      assert html =~ "60 vulnerability fixes per month"
      assert html =~ "Additional fixes at $15 each"

      # Enterprise tier
      assert html =~ "Custom"
      assert html =~ "pricing"
    end

    test "Pro tier is highlighted (middle tier)", %{conn: conn} do
      {:ok, view, html} = live(conn, ~p"/pricing")

      # The Pro tier should have the highlighted styling
      # (dark background with shadow-2xl)
      assert html =~ "bg-gray-900"
      assert html =~ "shadow-2xl"
      assert html =~ "Start Pro Trial"
    end

    test "displays feature lists for each tier", %{conn: conn} do
      {:ok, _view, html} = live(conn, ~p"/pricing")

      # Free tier features
      assert html =~ "10 vulnerability fixes"
      assert html =~ "All security frameworks"
      assert html =~ "No credit card required"

      # Pro tier features
      assert html =~ "Priority AI processing"
      assert html =~ "Advanced analytics dashboard"
      assert html =~ "Dedicated support"
      assert html =~ "SLA guarantee"

      # Enterprise features
      assert html =~ "Unlimited fixes"
      assert html =~ "Self-hosted options"
      assert html =~ "SOC 2 / ISO 27001 compliance"
      assert html =~ "Dedicated account manager"
    end

    test "CTAs link to correct destinations", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/pricing")

      # Free tier CTA -> /signup
      assert view |> element("a[href='/signup']") |> has_element?()

      # Pro tier CTA -> /signup?plan=pro
      assert view |> element("a[href='/signup?plan=pro']") |> has_element?()

      # Enterprise CTA -> /contact
      assert view |> element("a[href='/contact']") |> has_element?()
    end

    test "displays FAQ section", %{conn: conn} do
      {:ok, _view, html} = live(conn, ~p"/pricing")

      assert html =~ "Frequently Asked Questions"

      # Key FAQ questions from RFC-066
      assert html =~ "What counts as a 'fix'?"
      assert html =~ "When does billing start?"
      assert html =~ "How do credits work?"
      assert html =~ "What if I exceed 60 fixes on the Pro plan?"
      assert html =~ "Can I cancel anytime?"
    end

    test "FAQ answers reference correct pricing", %{conn: conn} do
      {:ok, _view, html} = live(conn, ~p"/pricing")

      # Check that FAQ content matches RFC-066 pricing
      assert html =~ "10 free credits"
      assert html =~ "$29 per fix"  # PAYG rate
      assert html =~ "$15 per additional fix"  # Pro overage rate
      assert html =~ "60 credits each month"  # Pro included
    end

    test "includes 'Contact Us' CTA at bottom of FAQ", %{conn: conn} do
      {:ok, view, html} = live(conn, ~p"/pricing")

      assert html =~ "Still have questions?"
      assert view |> element("a[href='/contact']") |> has_element?()
    end

    test "sets page title to 'Pricing'", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/pricing")

      assert page_title(view) =~ "Pricing"
    end

    test "renders with gradient decoration", %{conn: conn} do
      {:ok, _view, html} = live(conn, ~p"/pricing")

      # Component includes gradient decoration
      assert html =~ "relative isolate"
    end

    test "displays section heading and description", %{conn: conn} do
      {:ok, _view, html} = live(conn, ~p"/pricing")

      assert html =~ "Choose the right plan for you"
      assert html =~ "Start with 10 free credits"
    end
  end

  describe "pricing page with feature flag OFF" do
    setup do
      # Disable flag for these tests using sandbox-safe helper
      FunWithFlagsHelper.disable_flag(:public_site)
      :ok
    end

    test "returns 404 or redirects when flag is disabled", %{conn: conn} do
      # The :require_public_site pipeline should redirect to fallback_url
      {:error, {:redirect, %{to: redirect_path}}} = live(conn, ~p"/pricing")

      # Should redirect to root (as configured in router)
      assert redirect_path == "/"
    end

    test "does not render pricing content when flag is OFF", %{conn: conn} do
      # Attempting to access should not show pricing content
      assert {:error, {:redirect, _}} = live(conn, ~p"/pricing")
    end
  end

  describe "mobile responsiveness" do
    setup do
      FunWithFlagsHelper.enable_flag(:public_site)
      :ok
    end

    test "uses responsive grid classes for 3 tiers", %{conn: conn} do
      {:ok, _view, html} = live(conn, ~p"/pricing")

      # Should use grid-cols-1 on mobile, grid-cols-3 on large screens
      assert html =~ "grid-cols-1"
      assert html =~ "lg:grid-cols-3"
    end

    test "FAQ section is readable on mobile", %{conn: conn} do
      {:ok, _view, html} = live(conn, ~p"/pricing")

      # FAQ uses responsive padding
      assert html =~ "px-6"  # Mobile padding
      assert html =~ "lg:px-8"  # Desktop padding
    end
  end

  describe "dark mode compatibility" do
    setup do
      FunWithFlagsHelper.enable_flag(:public_site)
      :ok
    end

    test "includes dark mode classes for background", %{conn: conn} do
      {:ok, _view, html} = live(conn, ~p"/pricing")

      assert html =~ "dark:bg-gray-900"
      assert html =~ "dark:bg-gray-800"
    end

    test "includes dark mode classes for text", %{conn: conn} do
      {:ok, _view, html} = live(conn, ~p"/pricing")

      assert html =~ "dark:text-white"
      assert html =~ "dark:text-gray-400"
      assert html =~ "dark:text-blue-400"
    end

    test "FAQ section has dark mode support", %{conn: conn} do
      {:ok, _view, html} = live(conn, ~p"/pricing")

      # FAQ background and text should have dark variants
      assert html =~ "dark:bg-gray-800"
      assert html =~ "dark:text-white"
      assert html =~ "dark:text-gray-400"
    end
  end

  describe "accessibility" do
    setup do
      FunWithFlagsHelper.enable_flag(:public_site)
      :ok
    end

    test "pricing tiers have proper IDs for aria-describedby", %{conn: conn} do
      {:ok, _view, html} = live(conn, ~p"/pricing")

      assert html =~ "tier-free"
      assert html =~ "tier-pro"
      assert html =~ "tier-enterprise"
    end

    test "CTA buttons have aria-describedby attributes", %{conn: conn} do
      {:ok, _view, html} = live(conn, ~p"/pricing")

      assert html =~ ~r/aria-describedby="tier-/
    end

    test "uses semantic HTML for FAQ (dl, dt, dd)", %{conn: conn} do
      {:ok, _view, html} = live(conn, ~p"/pricing")

      # FAQ uses definition list semantics
      assert html =~ "<dl"
      assert html =~ "<dt"
      assert html =~ "<dd"
    end
  end

  describe "integration with billing context" do
    setup do
      FunWithFlagsHelper.enable_flag(:public_site)
      :ok
    end

    test "pricing amounts match RFC-066 billing configuration", %{conn: conn} do
      {:ok, _view, html} = live(conn, ~p"/pricing")

      # These values should match lib/rsolv/billing/pricing.ex
      # PAYG: $29/fix (2900 cents)
      assert html =~ "$29"

      # Pro: $599/month (59900 cents)
      assert html =~ "$599"

      # Pro additional: $15/fix (1500 cents)
      assert html =~ "$15"
    end

    test "free credit amounts match customer onboarding flow", %{conn: conn} do
      {:ok, _view, html} = live(conn, ~p"/pricing")

      # Should reference the correct free credit amounts from RFC-065/066:
      # 5 on signup + 5 when adding payment = 10 total
      assert html =~ "10 free credits"
      assert html =~ "5 credits on signup"
      assert html =~ "5 more when you add a payment method"
    end
  end
end
