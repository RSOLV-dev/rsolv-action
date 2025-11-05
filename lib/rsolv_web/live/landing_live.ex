defmodule RsolvWeb.LandingLive do
  @moduledoc """
  RFC-078: Public Site Landing Page (/)

  Main landing page for self-service customer acquisition.
  Displays value proposition, features, social proof, and pricing teaser.

  Protected by :public_site feature flag via router pipeline.
  """
  use RsolvWeb, :live_view

  import RsolvWeb.MarketingComponents

  # Import new Tailwind Plus marketing components
  alias RsolvWeb.Components.Marketing.HeroSimpleCentered
  alias RsolvWeb.Components.Marketing.FeaturesGrid2x2
  alias RsolvWeb.Components.Marketing.CtaSimpleCentered

  alias RsolvWeb.Services.Analytics
  alias RsolvWeb.Helpers.TrackingHelper

  @impl true
  def mount(params, _session, socket) do
    # Feature flag check handled by router pipeline :require_public_site
    socket =
      socket
      |> assign(:mobile_menu_open, false)
      |> assign(:features, features())
      |> TrackingHelper.assign_utm_params(params)

    # Track page view
    referrer = socket.assigns[:referrer]
    tracking_data = TrackingHelper.extract_tracking_data(socket)
    Analytics.track_page_view("/landing", referrer, tracking_data)

    {:ok, socket}
  end

  @impl true
  def handle_event("toggle_mobile_menu", _params, socket) do
    {:noreply, assign(socket, :mobile_menu_open, !socket.assigns.mobile_menu_open)}
  end

  @impl true
  def handle_event("close_mobile_menu", _params, socket) do
    {:noreply, assign(socket, :mobile_menu_open, false)}
  end

  @impl true
  def handle_event("track_cta_click", %{"destination" => destination}, socket) do
    tracking_data =
      socket
      |> TrackingHelper.extract_tracking_data()
      |> Map.merge(%{destination: destination, cta_type: "primary"})

    Analytics.track("cta_click", tracking_data)
    {:noreply, socket}
  end

  # Private functions

  defp features do
    [
      %{
        icon:
          ~S'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" class="size-6 text-white"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" /></svg>',
        title: "Real Vulnerabilities",
        description:
          "Not false positives - only actionable security issues validated by AST analysis."
      },
      %{
        icon:
          ~S'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" class="size-6 text-white"><path stroke-linecap="round" stroke-linejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z" /></svg>',
        title: "Verified Fixes",
        description:
          "Every fix is tested to ensure it resolves the vulnerability without breaking functionality."
      },
      %{
        icon:
          ~S'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" class="size-6 text-white"><path stroke-linecap="round" stroke-linejoin="round" d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" /></svg>',
        title: "Lightning Fast",
        description:
          "Fixes generated and tested in minutes, not days. Get pull requests ready to merge."
      },
      %{
        icon:
          ~S'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" class="size-6 text-white"><path stroke-linecap="round" stroke-linejoin="round" d="M2.25 18 9 11.25l4.306 4.306a11.95 11.95 0 0 1 5.814-5.518l2.74-1.22m0 0-5.94-2.281m5.94 2.28-2.28 5.941" /></svg>',
        title: "Continuous Security",
        description:
          "Automated scanning and fixing integrated into your development workflow."
      }
    ]
  end
end
