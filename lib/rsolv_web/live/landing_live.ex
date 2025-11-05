defmodule RsolvWeb.LandingLive do
  @moduledoc """
  RFC-078: Public Site Landing Page (/)

  Main landing page for self-service customer acquisition.
  Displays value proposition, features, social proof, and pricing teaser.

  Protected by :public_site feature flag via router pipeline.
  """
  use RsolvWeb, :live_view

  import RsolvWeb.MarketingComponents

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
          ~s(<svg class="w-12 h-12 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>),
        title: "Detects Real Vulnerabilities",
        description: "Not false positives - only actionable security issues"
      },
      %{
        icon:
          ~s(<svg class="w-12 h-12 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path></svg>),
        title: "Generates Tested Fixes",
        description: "Automated remediation with validation tests"
      },
      %{
        icon:
          ~s(<svg class="w-12 h-12 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"></path></svg>),
        title: "Creates Pull Requests",
        description: "Ready-to-review PRs with complete validation"
      },
      %{
        icon:
          ~s(<svg class="w-12 h-12 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 6l3 1m0 0l-3 9a5.002 5.002 0 006.001 0M6 7l3 9M6 7l6-2m6 2l3-1m-3 1l-3 9a5.002 5.002 0 006.001 0M18 7l3 9m-3-9l-6-2m0-2v2m0 16V5m0 16H9m3 0h3"></path></svg>),
        title: "Multi-Language Support",
        description: "JavaScript, Python, Ruby, and more"
      }
    ]
  end
end
