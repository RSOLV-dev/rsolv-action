defmodule RsolvWeb.Components.ThemeToggleTest do
  use ExUnit.Case, async: true
  import Phoenix.Component
  import Phoenix.LiveViewTest

  alias RsolvWeb.Components.ThemeToggle

  describe "theme_toggle/1" do
    test "renders theme toggle button with correct structure" do
      assigns = %{}

      html =
        rendered_to_string(~H"""
        <ThemeToggle.theme_toggle />
        """)

      # Check button attributes
      # ID is now optional, check for data attribute instead
      assert html =~ ~s(data-theme-toggle)
      assert html =~ ~s(data-theme-toggle)
      assert html =~ ~s(aria-label="Toggle dark mode")

      # Check both icons are present
      # Icons now use classes instead of IDs
      assert html =~ ~s(class="theme-toggle-light-icon)
      assert html =~ ~s(class="theme-toggle-dark-icon)
    end

    test "renders sun icon with correct classes for dark mode visibility" do
      assigns = %{}

      html =
        rendered_to_string(~H"""
        <ThemeToggle.theme_toggle />
        """)

      # Sun icon should have classes: hidden dark:block
      # Sun icon should have classes: hidden dark:block
      assert html =~ ~r/class="theme-toggle-light-icon[^"]*hidden[^"]*dark:block/
    end

    test "renders moon icon with correct classes for light mode visibility" do
      assigns = %{}

      html =
        rendered_to_string(~H"""
        <ThemeToggle.theme_toggle />
        """)

      # Moon icon should have classes: block dark:hidden
      # Moon icon should have classes: block dark:hidden
      assert html =~ ~r/class="theme-toggle-dark-icon[^"]*block[^"]*dark:hidden/
    end

    test "accepts and applies additional classes" do
      assigns = %{class: "ml-4 custom-class"}

      html =
        rendered_to_string(~H"""
        <ThemeToggle.theme_toggle class={@class} />
        """)

      assert html =~ "ml-4 custom-class"
    end

    test "button has focus and hover states" do
      assigns = %{}

      html =
        rendered_to_string(~H"""
        <ThemeToggle.theme_toggle />
        """)

      assert html =~ "hover:bg-gray-100"
      assert html =~ "dark:hover:bg-gray-800"
      assert html =~ "focus:outline-none"
      assert html =~ "focus:ring-2"
      assert html =~ "focus:ring-brand-blue"
    end

    test "icons have correct SVG structure" do
      assigns = %{}

      html =
        rendered_to_string(~H"""
        <ThemeToggle.theme_toggle />
        """)

      # Check sun icon SVG
      assert html =~ ~s(viewBox="0 0 24 24")
      # Sun path
      assert html =~ ~s(M12 3v1m0 16v1m9-9h-1M4 12H3)

      # Check moon icon SVG
      # Moon path
      assert html =~ ~s(M17.293 13.293A8 8 0 016.707 2.707)
    end
  end
end
