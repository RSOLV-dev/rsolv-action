defmodule RsolvWeb.Components.ThemeToggle do
  use Phoenix.Component

  @doc """
  Renders a theme toggle button that switches between light and dark modes.
  Works on both LiveView and regular controller pages.

  ## Examples

      <.theme_toggle />
      <.theme_toggle class="ml-4" />
  """
  def theme_toggle(assigns) do
    assigns = assign_new(assigns, :class, fn -> "" end)
    assigns = assign_new(assigns, :id, fn -> nil end)

    ~H"""
    <button
      type="button"
      id={@id}
      data-theme-toggle
      class={[
        @class,
        "relative inline-flex h-8 w-8 items-center justify-center",
        "rounded-lg transition-colors",
        "hover:bg-gray-100 dark:hover:bg-gray-800",
        "focus:outline-none focus:ring-2 focus:ring-brand-blue focus:ring-offset-2",
        "dark:focus:ring-offset-gray-900"
      ]}
      aria-label="Toggle dark mode"
    >
      <!-- Sun icon (visible in dark mode) -->
      <svg
        class="theme-toggle-light-icon hidden dark:block w-5 h-5 text-yellow-400"
        fill="currentColor"
        viewBox="0 0 24 24"
        stroke="none"
      >
        <path
          d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
          stroke-linejoin="round"
          fill="none"
        />
      </svg>
      
    <!-- Moon icon (visible in light mode) -->
      <svg
        class="theme-toggle-dark-icon block dark:hidden w-5 h-5 text-gray-600 dark:text-gray-400"
        fill="currentColor"
        viewBox="0 0 24 24"
        stroke="none"
      >
        <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z" />
      </svg>
    </button>
    """
  end
end
