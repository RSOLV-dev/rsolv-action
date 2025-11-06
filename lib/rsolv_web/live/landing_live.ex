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
  alias RsolvWeb.Components.Marketing.Icons

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
        icon: Icons.checkmark_circle(),
        title: "Real Vulnerabilities",
        description:
          "Not false positives - only actionable security issues validated by AST analysis."
      },
      %{
        icon: Icons.lock(),
        title: "Verified Fixes",
        description:
          "Every fix is tested to ensure it resolves the vulnerability without breaking functionality."
      },
      %{
        icon: Icons.lightning(),
        title: "Lightning Fast",
        description:
          "Fixes generated and tested in minutes, not days. Get pull requests ready to merge."
      },
      %{
        icon: Icons.chart_up(),
        title: "Continuous Security",
        description:
          "Automated scanning and fixing integrated into your development workflow."
      }
    ]
  end
end
