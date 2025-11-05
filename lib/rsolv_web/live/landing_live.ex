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
end
