defmodule RsolvWeb.Features.DarkModeTest do
  use RsolvWeb.ConnCase, async: false
  import Phoenix.ConnTest

  @moduletag :feature_test

  describe "dark mode functionality" do
    test "pages include theme initialization script", %{conn: conn} do
      conn = get(conn, ~p"/")

      response = html_response(conn, 200)

      # Check for theme initialization script
      assert response =~ "localStorage.getItem('theme')"
      assert response =~ "window.matchMedia('(prefers-color-scheme: dark)')"
      assert response =~ "document.documentElement.classList.toggle('dark'"
    end

    test "blog pages include theme toggle", %{conn: conn} do
      # Enable blog feature flags
      FunWithFlags.enable(:blog)
      FunWithFlags.enable(:display_draft_blog_posts)

      conn = get(conn, ~p"/blog")
      response = html_response(conn, 200)

      # Check for theme toggle button
      # Check for theme toggle button with data attribute
      assert response =~ ~s(data-theme-toggle)
      # Icons now use classes instead of IDs
      assert response =~ ~s(class="theme-toggle-light-icon)
      assert response =~ ~s(class="theme-toggle-dark-icon)
    end

    test "theme toggle handler is present in layout", %{conn: conn} do
      conn = get(conn, ~p"/")
      response = html_response(conn, 200)

      # Check for click handler
      assert response =~ "document.addEventListener('click'"
      assert response =~ "[data-theme-toggle]"
      assert response =~ "localStorage.setItem('theme'"
    end

    test "CSS includes dark mode styles", %{conn: conn} do
      conn = get(conn, ~p"/")
      response = html_response(conn, 200)

      # Check that app.css is loaded
      assert response =~ "/assets/app.css"

      # Check for dark mode classes in HTML
      assert response =~ "dark:"
    end

    test "header component includes theme toggle", %{conn: conn} do
      conn = get(conn, ~p"/")
      response = html_response(conn, 200)

      # Check header has theme toggle
      # Check header has theme toggle with data attribute
      assert response =~ ~r/<header[^>]*>.*data-theme-toggle.*<\/header>/s
    end
  end

  describe "CSS compilation" do
    test "dark mode CSS variables are defined in compiled CSS" do
      # Verify compiled CSS exists and contains dark mode styles
      css_path = Path.join([File.cwd!(), "priv", "static", "assets", "app.css"])

      assert File.exists?(css_path),
             "Compiled CSS not found at #{css_path}. Run: mix assets.build"

      css_content = File.read!(css_path)

      # Check for dark mode class selector
      assert css_content =~ ".dark",
             "Dark mode class selector not found in compiled CSS"

      # Check for dark mode utility classes (Tailwind generates these)
      # Example: dark:bg-slate-950, dark:text-white, etc.
      assert css_content =~ "dark:",
             "Dark mode utility classes not found in compiled CSS"

      # Verify we have actual dark mode color values
      # Tailwind compiles these to actual hex/rgb values
      assert String.length(css_content) > 1000,
             "Compiled CSS is too small, may not be properly built"
    end
  end
end
