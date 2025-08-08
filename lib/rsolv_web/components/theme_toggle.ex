defmodule RsolvWeb.Components.ThemeToggle do
  use Phoenix.Component

  @doc """
  Renders a theme toggle button that switches between light and dark modes.
  
  ## Examples
  
      <.theme_toggle />
      <.theme_toggle class="ml-4" />
  """
  def theme_toggle(assigns) do
    assigns = assign_new(assigns, :class, fn -> "" end)
    assigns = assign_new(assigns, :variant, fn -> "default" end)
    
    ~H"""
    <button
      type="button"
      id="theme-toggle"
      phx-update="ignore"
      phx-hook="DarkThemeToggle"
      class={"#{@class} relative inline-flex h-8 w-8 items-center justify-center rounded-lg transition-colors hover:bg-gray-100 dark:hover:bg-dark-700 focus:outline-none focus:ring-2 focus:ring-brand-blue focus:ring-offset-2 dark:focus:ring-offset-dark-900"}
      aria-label="Toggle dark mode"
    >
      <!-- Sun icon (visible in dark mode) -->
      <svg
        id="theme-toggle-light-icon"
        class="w-5 h-5 text-transparent hidden"
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
        id="theme-toggle-dark-icon"
        class="w-5 h-5 text-transparent"
        fill="currentColor"
        viewBox="0 0 24 24"
        stroke="none"
      >
        <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z" />
      </svg>
    </button>
    
    <script>
      // Toggle early based on <html class="dark">
      const themeToggleDarkIcon = document.getElementById('theme-toggle-dark-icon');
      const themeToggleLightIcon = document.getElementById('theme-toggle-light-icon');
      if (themeToggleDarkIcon != null && themeToggleLightIcon != null) {
        let dark = document.documentElement.classList.contains('dark');
        let variant = '<%= @variant %>';
        const show = dark ? themeToggleLightIcon : themeToggleDarkIcon;
        const hide = dark ? themeToggleDarkIcon : themeToggleLightIcon;
        show.classList.remove('hidden', 'text-transparent');
        // On homepage, use white icon in light mode for visibility on dark header
        const lightModeColor = variant === 'homepage' ? 'text-white' : 'text-gray-600';
        show.classList.add(dark ? 'text-yellow-400' : lightModeColor);
        hide.classList.add('hidden', 'text-transparent');
      }
    </script>
    """
  end
end