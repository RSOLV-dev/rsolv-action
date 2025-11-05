defmodule RsolvWeb.Helpers.TrackingHelper do
  @moduledoc """
  Shared helpers for analytics tracking across LiveViews and Controllers.

  Provides utilities for:
  - Generating anonymous tracking IDs
  - Extracting tracking data from connections/sockets
  - Assigning UTM parameters to sockets
  """

  @doc """
  Generates a cryptographically secure tracking ID.

  ## Examples

      iex> id = TrackingHelper.generate_tracking_id()
      iex> String.length(id)
      32
  """
  def generate_tracking_id do
    :crypto.strong_rand_bytes(16)
    |> Base.encode16(case: :lower)
  end

  @doc """
  Extracts tracking data from a LiveView socket.

  Builds a map containing user_id, timestamp, page path, referrer, and UTM parameters.
  """
  def extract_tracking_data(%Phoenix.LiveView.Socket{} = socket) do
    %{
      user_id: generate_tracking_id(),
      timestamp: DateTime.utc_now() |> DateTime.to_string(),
      page_path: socket.assigns[:current_path] || "/",
      referrer: socket.assigns[:referrer],
      utm_source: socket.assigns[:utm_source],
      utm_medium: socket.assigns[:utm_medium],
      utm_campaign: socket.assigns[:utm_campaign],
      utm_term: socket.assigns[:utm_term],
      utm_content: socket.assigns[:utm_content]
    }
  end

  @doc """
  Assigns UTM parameters from params to a LiveView socket.

  ## Examples

      socket = assign_utm_params(socket, %{"utm_source" => "github"})
  """
  def assign_utm_params(socket, params) do
    socket
    |> Phoenix.Component.assign(:utm_source, params["utm_source"])
    |> Phoenix.Component.assign(:utm_medium, params["utm_medium"])
    |> Phoenix.Component.assign(:utm_campaign, params["utm_campaign"])
    |> Phoenix.Component.assign(:utm_term, params["utm_term"])
    |> Phoenix.Component.assign(:utm_content, params["utm_content"])
  end
end
