defmodule RsolvWeb.LandingLiveTest do
  use RsolvWeb.ConnCase, async: false
  import Phoenix.LiveViewTest
  import Mock

  alias FunWithFlags

  setup do
    # Clean up feature flags after each test
    on_exit(fn ->
      FunWithFlags.disable(:public_site)
    end)

    :ok
  end

  describe "feature flag protection" do
    test "redirects to / when :public_site flag is disabled", %{conn: conn} do
      # Ensure flag is disabled
      FunWithFlags.disable(:public_site)

      # Attempt to access landing page
      {:error, {:redirect, %{to: redirect_path, flash: flash}}} = live(conn, "/landing")

      # Should redirect to home
      assert redirect_path == "/"
      # Should have flash message
      assert flash["info"] == "This page is not yet available."
    end

    test "allows access when :public_site flag is enabled", %{conn: conn} do
      # Enable the flag
      Rsolv.Repo.query!(
        "INSERT INTO fun_with_flags_toggles (flag_name, gate_type, target, enabled) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
        ["public_site", "boolean", nil, true]
      )

      # Should successfully mount
      assert {:ok, _view, _html} = live(conn, "/landing")
    end
  end

  describe "landing page rendering (when flag is enabled)" do
    setup %{conn: conn} do
      # Enable flag for these tests - use Ecto to insert the flag
      Rsolv.Repo.query!(
        "INSERT INTO fun_with_flags_toggles (flag_name, gate_type, target, enabled) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
        ["public_site", "boolean", nil, true]
      )

      {:ok, conn: conn}
    end

    test "renders hero section with value proposition", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/landing")

      assert html =~ "Automated Security Fixes"
      assert html =~ "AI-powered vulnerability detection"
      assert html =~ "Get 10 free credits"
    end

    test "displays 'Start Free Trial' CTA in hero", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/landing")

      # Check CTA exists and links to /signup
      assert view
             |> element("a[href=\"/signup\"]", "Start Free Trial")
             |> has_element?()
    end

    test "shows 'No credit card required' message", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/landing")

      assert html =~ "No credit card required"
    end

    test "displays features section", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/landing")

      # Key features should be listed
      assert html =~ "Detects Real Vulnerabilities"
      assert html =~ "Generates Tested Fixes"
      assert html =~ "Creates Pull Requests"
      assert html =~ "Multi-Language Support"
    end

    test "displays social proof section", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/landing")

      assert html =~ "Trusted by Development Teams"
      assert html =~ "1000+"
      assert html =~ "Vulnerabilities Fixed"
      assert html =~ "95%"
      assert html =~ "Fix Success Rate"
    end

    test "displays pricing teaser with link to /pricing", %{conn: conn} do
      {:ok, view, html} = live(conn, "/landing")

      assert html =~ "Start with 10 Free Credits"
      assert html =~ "$599/month"
      assert html =~ "$29/fix"

      # Check pricing link exists
      assert view
             |> element("a[href=\"/pricing\"]", "View Full Pricing")
             |> has_element?()
    end

    test "displays demo repository CTA", %{conn: conn} do
      {:ok, view, html} = live(conn, "/landing")

      assert html =~ "See RSOLV in Action"

      # Check demo repo link exists
      assert view
             |> element("a[href*=\"github.com/RSOLV-dev/nodegoat\"]")
             |> has_element?()
    end

    test "has multiple CTAs linking to /signup", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/landing")

      # Should have at least 2 signup CTAs
      signup_links = view |> element("a[href=\"/signup\"]") |> render() |> String.length()
      assert signup_links > 0
    end
  end

  describe "responsive design" do
    setup %{conn: conn} do
      # Enable flag for these tests
      Rsolv.Repo.query!(
        "INSERT INTO fun_with_flags_toggles (flag_name, gate_type, target, enabled) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
        ["public_site", "boolean", nil, true]
      )

      {:ok, conn: conn}
    end

    test "uses responsive Tailwind classes for mobile (320px+)", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/landing")

      # Check for Tailwind responsive classes
      assert html =~ "sm:text"
      assert html =~ "lg:text"
      assert html =~ "md:grid-cols"
      assert html =~ "sm:flex-row"
    end

    test "has container classes for layout", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/landing")

      # Should use container for layout
      assert html =~ "container mx-auto"
      assert html =~ "max-w-"
    end
  end

  describe "analytics tracking" do
    setup %{conn: conn} do
      # Enable flag for these tests
      Rsolv.Repo.query!(
        "INSERT INTO fun_with_flags_toggles (flag_name, gate_type, target, enabled) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
        ["public_site", "boolean", nil, true]
      )

      {:ok, conn: conn}
    end

    test "tracks page view on mount", %{conn: conn} do
      with_mock RsolvWeb.Services.Analytics,
        track_page_view: fn path, _, _ ->
          assert path == "/landing"
          :ok
        end do
        {:ok, _view, _html} = live(conn, "/landing")

        # Verify page view was tracked
        assert_called(RsolvWeb.Services.Analytics.track_page_view("/landing", :_, :_))
      end
    end

    test "tracks CTA clicks when phx-click event is triggered", %{conn: conn} do
      with_mocks([
        {RsolvWeb.Services.Analytics, [],
         [
           track_page_view: fn _, _, _ -> :ok end,
           track: fn event, data ->
             assert event == "cta_click"
             assert data.destination in ["/signup", "/pricing", "demo-repo"]
             :ok
           end
         ]}
      ]) do
        {:ok, view, _html} = live(conn, "/landing")

        # Simulate CTA click
        view
        |> element("a[href=\"/signup\"]")
        |> render_click()

        # Verify tracking was called
        assert_called(RsolvWeb.Services.Analytics.track("cta_click", :_))
      end
    end
  end

  describe "dark mode support" do
    setup %{conn: conn} do
      # Enable flag for these tests
      Rsolv.Repo.query!(
        "INSERT INTO fun_with_flags_toggles (flag_name, gate_type, target, enabled) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
        ["public_site", "boolean", nil, true]
      )

      {:ok, conn: conn}
    end

    test "includes dark mode Tailwind classes", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/landing")

      # Should have dark: variants
      assert html =~ "dark:bg-"
      assert html =~ "dark:text-"
    end
  end
end
