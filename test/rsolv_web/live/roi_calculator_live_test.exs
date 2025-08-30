defmodule RsolvWeb.RoiCalculatorLiveTest do
  use RsolvWeb.ConnCase
  import Phoenix.LiveViewTest

  describe "ROI Calculator LiveComponent" do
    test "renders on homepage with default values", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")
      
      # Verify the ROI calculator component is rendered
      assert html =~ "ROI Calculator"
      assert html =~ "50 issues/month"
      assert html =~ "6 hours"  # Updated to match new defaults: 5.5 dev + 1.5 coordination
      assert html =~ "$85/hour"  # Updated to match new defaults: $130K salary + overhead
      assert html =~ "80% deployed"
      
      # Verify default calculations
      assert html =~ "40/month" # fixes deployed (50 * 0.8)
      assert html =~ "240 hours" # time saved (40 * 6)
      assert html =~ "$600" # pay as you go cost
      assert html =~ "$499" # teams plan cost
    end

    test "shows appropriate pricing plan recommendations", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")
      
      # With default values (50 issues, 80% deployment = 40 fixes)
      # Teams plan ($499 + $0 extra) should be recommended over pay-as-you-go ($600)
      assert html =~ "Teams Plan"
      assert html =~ "Recommended"
    end

    test "displays pricing options", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")
      
      # Verify both pricing plans are shown
      assert html =~ "Pay As You Go"
      assert html =~ "$15 per fix deployed"
      assert html =~ "No monthly commitment"
      
      assert html =~ "Teams Plan"
      assert html =~ "60 fixes included"
      assert html =~ "$8 per additional fix"
    end

    test "shows ROI metrics", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")
      
      # Verify ROI summary section
      assert html =~ "Monthly ROI"
      assert html =~ "Payback Period"
      assert html =~ "Annual Value"
      assert html =~ "%"
    end

    test "includes GitHub integration section", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")
      
      assert html =~ "Seamless GitHub Integration"
      assert html =~ "Automated vulnerability detection on every push"
      assert html =~ "One-click fixes via pull requests"
      assert html =~ "Works with your existing CI/CD pipeline"
    end
  end
end