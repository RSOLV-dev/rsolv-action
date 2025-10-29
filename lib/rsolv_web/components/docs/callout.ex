defmodule RsolvWeb.Components.Docs.Callout do
  use Phoenix.Component

  @doc """
  Renders a callout box for important information, warnings, or tips.

  Supports multiple variants with appropriate styling and icons:
  - `info` (default): Blue, for informational content
  - `warning`: Yellow/orange, for cautions and warnings
  - `error`: Red, for errors and critical information
  - `success`: Green, for successful operations or tips
  - `note`: Gray, for general notes

  ## Examples

      <.callout>
        This is a default info callout.
      </.callout>

      <.callout variant="warning" title="Important">
        Make sure to backup your data first!
      </.callout>

      <.callout variant="error">
        This operation cannot be undone.
      </.callout>

  ## Attributes

  - `variant` - One of: info, warning, error, success, note (default: "info")
  - `title` - Optional title for the callout
  - `class` - Additional CSS classes
  """
  attr :variant, :string, default: "info", values: ["info", "warning", "error", "success", "note"]
  attr :title, :string, default: nil
  attr :class, :string, default: ""
  slot :inner_block, required: true

  def callout(assigns) do
    ~H"""
    <div
      class={[
        "rounded-lg border p-4",
        callout_classes(@variant),
        @class
      ]}
      role="note"
    >
      <div class="flex items-start">
        <div class="flex-shrink-0">
          {render_icon(@variant)}
        </div>
        <div class="ml-3 flex-1">
          <%= if @title do %>
            <h3 class={["text-sm font-semibold mb-1", title_color(@variant)]}>
              {@title}
            </h3>
          <% end %>
          <div class={["text-sm", content_color(@variant)]}>
            {render_slot(@inner_block)}
          </div>
        </div>
      </div>
    </div>
    """
  end

  defp callout_classes("info") do
    "bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800"
  end

  defp callout_classes("warning") do
    "bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800"
  end

  defp callout_classes("error") do
    "bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800"
  end

  defp callout_classes("success") do
    "bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800"
  end

  defp callout_classes("note") do
    "bg-slate-50 dark:bg-slate-800 border-slate-200 dark:border-slate-700"
  end

  defp title_color("info"), do: "text-blue-900 dark:text-blue-100"
  defp title_color("warning"), do: "text-yellow-900 dark:text-yellow-100"
  defp title_color("error"), do: "text-red-900 dark:text-red-100"
  defp title_color("success"), do: "text-green-900 dark:text-green-100"
  defp title_color("note"), do: "text-slate-900 dark:text-slate-100"

  defp content_color("info"), do: "text-blue-800 dark:text-blue-200"
  defp content_color("warning"), do: "text-yellow-800 dark:text-yellow-200"
  defp content_color("error"), do: "text-red-800 dark:text-red-200"
  defp content_color("success"), do: "text-green-800 dark:text-green-200"
  defp content_color("note"), do: "text-slate-700 dark:text-slate-300"

  defp icon_color("info"), do: "text-blue-600 dark:text-blue-400"
  defp icon_color("warning"), do: "text-yellow-600 dark:text-yellow-400"
  defp icon_color("error"), do: "text-red-600 dark:text-red-400"
  defp icon_color("success"), do: "text-green-600 dark:text-green-400"
  defp icon_color("note"), do: "text-slate-600 dark:text-slate-400"

  defp render_icon(variant) do
    assigns = %{variant: variant}

    ~H"""
    <svg
      class={["h-5 w-5", icon_color(@variant)]}
      fill="currentColor"
      viewBox="0 0 20 20"
      aria-hidden="true"
    >
      <%= case @variant do %>
        <% "info" -> %>
          <path
            fill-rule="evenodd"
            d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z"
            clip-rule="evenodd"
          />
        <% "warning" -> %>
          <path
            fill-rule="evenodd"
            d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z"
            clip-rule="evenodd"
          />
        <% "error" -> %>
          <path
            fill-rule="evenodd"
            d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
            clip-rule="evenodd"
          />
        <% "success" -> %>
          <path
            fill-rule="evenodd"
            d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
            clip-rule="evenodd"
          />
        <% "note" -> %>
          <path
            fill-rule="evenodd"
            d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z"
            clip-rule="evenodd"
          />
      <% end %>
    </svg>
    """
  end
end
