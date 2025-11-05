defmodule RsolvWeb.LandingLive do
  @moduledoc """
  RFC-078: Public Site Landing Page (/)

  Main landing page for self-service customer acquisition.
  Displays value proposition, features, social proof, and pricing teaser.

  Protected by :public_site feature flag.
  """
  use RsolvWeb, :live_view
  require Logger
  alias RsolvWeb.Services.Analytics

  @impl true
  def mount(params, _session, socket) do
    # Feature flag check handled by router pipeline :require_public_site
    # Track page view with UTM params
    referrer = Map.get(socket.assigns, :referrer)
    Analytics.track_page_view("/landing", referrer, extract_tracking_data(socket))

    socket =
      socket
      |> assign(:mobile_menu_open, false)
      |> assign(:utm_source, params["utm_source"])
      |> assign(:utm_medium, params["utm_medium"])
      |> assign(:utm_campaign, params["utm_campaign"])
      |> assign(:utm_term, params["utm_term"])
      |> assign(:utm_content, params["utm_content"])

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
    # Track CTA clicks for conversion analytics
    tracking_data =
      extract_tracking_data(socket)
      |> Map.put(:destination, destination)
      |> Map.put(:cta_type, "primary")

    Analytics.track("cta_click", tracking_data)

    {:noreply, socket}
  end

  # Private helper functions

  defp generate_tracking_id do
    :crypto.strong_rand_bytes(16)
    |> Base.encode16(case: :lower)
  end

  defp extract_tracking_data(socket) do
    %{
      user_id: generate_tracking_id(),
      timestamp: DateTime.utc_now() |> DateTime.to_string(),
      page_path: "/landing",
      referrer: Map.get(socket.assigns, :referrer),
      utm_source: Map.get(socket.assigns, :utm_source),
      utm_medium: Map.get(socket.assigns, :utm_medium),
      utm_campaign: Map.get(socket.assigns, :utm_campaign)
    }
  end
end
