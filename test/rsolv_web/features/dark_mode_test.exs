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
    @tag :skip
    test "dark mode CSS variables are defined in compiled CSS" do
      # This test requires CSS to be compiled first
      # Run: cd assets && npm run build
      css_path = Path.join([File.cwd!(), "priv", "static", "assets", "app.css"])
      
      if File.exists?(css_path) do
        css_content = File.read!(css_path)
        
        # Check for CSS variables
        assert css_content =~ "--color-bg-canvas"
        assert css_content =~ ".dark"
        # Note: The compiled CSS won't have "colors.slate.950" but the actual color values
      else
        # Skip test if CSS not compiled yet
        IO.puts("Skipping CSS test - file not found at #{css_path}")
      end
    end
  end
end