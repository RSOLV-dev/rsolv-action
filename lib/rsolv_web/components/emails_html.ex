defmodule RsolvWeb.EmailsHTML do
  @moduledoc """
  Module for rendering email templates using Phoenix 1.7's approach.
  This replaces the old Phoenix.View based rendering.
  """
  use RsolvWeb, :html

  # Helper function to make assigns available
  defp assign_new_lazy(assigns, key, fun) do
    if Map.has_key?(assigns, key) do
      assigns
    else
      Map.put(assigns, key, fun.())
    end
  end

  # Helper to ensure default assigns are present
  def with_defaults(assigns) do
    assigns
    |> assign_new_lazy(:app_url, fn -> "https://rsolv.dev" end)
    |> assign_new_lazy(:docs_url, fn -> "https://rsolv.dev/docs" end)
    |> assign_new_lazy(:unsubscribe_url, fn ->
      "https://rsolv.dev/unsubscribe?email=#{assigns[:email]}"
    end)
    |> assign_new_lazy(:first_name, fn -> "there" end)
    |> assign_new_lazy(:email, fn -> "" end)
  end

  # Define template functions manually for now
  def early_access_guide(assigns) do
    ~H"""
    {Phoenix.HTML.raw(File.read!("lib/rsolv_web/components/templates/email/early_access_guide.html"))}
    """
  end

  def early_access_welcome(assigns) do
    ~H"""
    {Phoenix.HTML.raw(
      File.read!("lib/rsolv_web/components/templates/email/early_access_welcome.html")
    )}
    """
  end

  def feature_deep_dive(assigns) do
    ~H"""
    {Phoenix.HTML.raw(File.read!("lib/rsolv_web/components/templates/email/feature_deep_dive.html"))}
    """
  end

  def feedback_request(assigns) do
    ~H"""
    {Phoenix.HTML.raw(File.read!("lib/rsolv_web/components/templates/email/feedback_request.html"))}
    """
  end

  def first_issue(assigns) do
    ~H"""
    {Phoenix.HTML.raw(File.read!("lib/rsolv_web/components/templates/email/first_issue.html"))}
    """
  end

  def getting_started(assigns) do
    ~H"""
    {Phoenix.HTML.raw(File.read!("lib/rsolv_web/components/templates/email/getting_started.html"))}
    """
  end

  def setup_verification(assigns) do
    ~H"""
    {Phoenix.HTML.raw(File.read!("lib/rsolv_web/components/templates/email/setup_verification.html"))}
    """
  end

  def success_checkin(assigns) do
    ~H"""
    {Phoenix.HTML.raw(File.read!("lib/rsolv_web/components/templates/email/success_checkin.html"))}
    """
  end

  def welcome(assigns) do
    ~H"""
    {Phoenix.HTML.raw(File.read!("lib/rsolv_web/components/templates/email/welcome.html"))}
    """
  end

  # Render functions that add default assigns and return safe HTML strings
  def render_setup_verification(assigns) do
    assigns = with_defaults(assigns)
    html = setup_verification(assigns)
    Phoenix.HTML.Safe.to_iodata(html) |> IO.iodata_to_binary()
  end

  def render_feature_deep_dive(assigns) do
    assigns = with_defaults(assigns)
    html = feature_deep_dive(assigns)
    Phoenix.HTML.Safe.to_iodata(html) |> IO.iodata_to_binary()
  end

  def render_feedback_request(assigns) do
    assigns = with_defaults(assigns)
    html = feedback_request(assigns)
    Phoenix.HTML.Safe.to_iodata(html) |> IO.iodata_to_binary()
  end

  def render_success_checkin(assigns) do
    assigns = with_defaults(assigns)
    html = success_checkin(assigns)
    Phoenix.HTML.Safe.to_iodata(html) |> IO.iodata_to_binary()
  end

  def render_early_access_guide(assigns) do
    assigns = with_defaults(assigns)
    html = early_access_guide(assigns)
    Phoenix.HTML.Safe.to_iodata(html) |> IO.iodata_to_binary()
  end

  def render_early_access_welcome(assigns) do
    assigns = with_defaults(assigns)
    html = early_access_welcome(assigns)
    Phoenix.HTML.Safe.to_iodata(html) |> IO.iodata_to_binary()
  end

  def render_getting_started(assigns) do
    assigns = with_defaults(assigns)
    html = getting_started(assigns)
    Phoenix.HTML.Safe.to_iodata(html) |> IO.iodata_to_binary()
  end

  def render_welcome(assigns) do
    assigns = with_defaults(assigns)
    html = welcome(assigns)
    Phoenix.HTML.Safe.to_iodata(html) |> IO.iodata_to_binary()
  end

  def render_first_issue(assigns) do
    assigns = with_defaults(assigns)
    html = first_issue(assigns)
    Phoenix.HTML.Safe.to_iodata(html) |> IO.iodata_to_binary()
  end
end
