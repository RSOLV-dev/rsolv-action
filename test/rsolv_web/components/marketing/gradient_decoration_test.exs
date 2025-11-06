defmodule RsolvWeb.Components.Marketing.GradientDecorationTest do
  use RsolvWeb.ConnCase, async: true
  import Phoenix.LiveViewTest

  alias RsolvWeb.Components.Marketing.GradientDecoration

  describe "gradient_blur/1 with polygon variant" do
    test "renders top position polygon gradient by default" do
      assigns = %{}

      html = render_component(&GradientDecoration.gradient_blur/1, assigns)

      # Should include wrapper with top positioning
      assert html =~ "-top-40"
      assert html =~ "-z-10"
      assert html =~ "blur-3xl"

      # Should include gradient with rotation
      assert html =~ "rotate-[30deg]"
      assert html =~ "bg-gradient-to-tr"
      assert html =~ "from-blue-600"
      assert html =~ "to-emerald-600"
      assert html =~ "opacity-30"

      # Should include complex clip-path
      assert html =~ "clip-path: polygon"
      assert html =~ "74.1% 44.1%"
    end

    test "renders bottom position polygon gradient" do
      assigns = %{position: :bottom}

      html = render_component(&GradientDecoration.gradient_blur/1, assigns)

      # Should include wrapper with bottom positioning
      assert html =~ "top-[calc(100%-13rem)]"
      assert html =~ "-z-10"
      assert html =~ "blur-3xl"

      # Should include gradient without rotation
      refute html =~ "rotate-[30deg]"
      assert html =~ "bg-gradient-to-tr"
    end

    test "accepts custom colors for polygon gradient" do
      assigns = %{
        from_color: "purple-600",
        to_color: "pink-600"
      }

      html = render_component(&GradientDecoration.gradient_blur/1, assigns)

      assert html =~ "from-purple-600"
      assert html =~ "to-pink-600"
    end

    test "accepts custom opacity for polygon gradient" do
      assigns = %{opacity: "50"}

      html = render_component(&GradientDecoration.gradient_blur/1, assigns)

      assert html =~ "opacity-50"
    end

    test "includes aria-hidden for accessibility" do
      assigns = %{}

      html = render_component(&GradientDecoration.gradient_blur/1, assigns)

      assert html =~ "aria-hidden=\"true\""
    end
  end

  describe "gradient_blur/1 with radial variant" do
    test "renders radial SVG gradient" do
      assigns = %{variant: :radial}

      html = render_component(&GradientDecoration.gradient_blur/1, assigns)

      # Should include SVG element
      assert html =~ "<svg"
      assert html =~ "viewBox=\"0 0 1024 1024\""
      assert html =~ "aria-hidden=\"true\""

      # Should include circle and radial gradient
      assert html =~ "<circle"
      assert html =~ "r=\"512\""
      assert html =~ "cx=\"512\""
      assert html =~ "cy=\"512\""
      assert html =~ "<radialGradient"
      assert html =~ "id=\"gradient-decoration\""
    end

    test "uses default blue-to-emerald colors for radial gradient" do
      assigns = %{variant: :radial}

      html = render_component(&GradientDecoration.gradient_blur/1, assigns)

      # Blue (3B82F6) and Emerald (10B981) hex colors
      assert html =~ "stop-color=\"#3B82F6\""
      assert html =~ "stop-color=\"#10B981\""
    end

    test "accepts custom colors for radial gradient" do
      assigns = %{
        variant: :radial,
        from_color: "purple-600",
        to_color: "pink-600"
      }

      html = render_component(&GradientDecoration.gradient_blur/1, assigns)

      # Purple (9333EA) and Pink (DB2777) hex colors
      assert html =~ "stop-color=\"#9333EA\""
      assert html =~ "stop-color=\"#DB2777\""
    end

    test "radial gradient has proper positioning classes" do
      assigns = %{variant: :radial}

      html = render_component(&GradientDecoration.gradient_blur/1, assigns)

      # Should include responsive positioning
      assert html =~ "absolute"
      assert html =~ "top-1/2"
      assert html =~ "left-1/2"
      assert html =~ "-z-10"
      # Fixed: Reduced from size-256 (1024px) to size-96 (384px) to prevent overflow
      assert html =~ "size-96"
      assert html =~ "-translate-y-1/2"
    end

    test "radial gradient has mask-image for fading effect" do
      assigns = %{variant: :radial}

      html = render_component(&GradientDecoration.gradient_blur/1, assigns)

      assert html =~ "[mask-image:radial-gradient(closest-side,white,transparent)]"
    end
  end

  describe "color mapping" do
    test "maps common Tailwind colors to hex values" do
      color_pairs = [
        {"blue-600", "3B82F6"},
        {"blue-500", "3B82F6"},
        {"emerald-600", "10B981"},
        {"emerald-500", "10B981"},
        {"purple-600", "9333EA"},
        {"pink-600", "DB2777"}
      ]

      for {tailwind_color, expected_hex} <- color_pairs do
        assigns = %{variant: :radial, from_color: tailwind_color}

        html = render_component(&GradientDecoration.gradient_blur/1, assigns)

        assert html =~ "stop-color=\"##{expected_hex}\"",
               "Expected #{tailwind_color} to map to ##{expected_hex}"
      end
    end

    test "defaults to blue for unknown colors" do
      assigns = %{variant: :radial, from_color: "unknown-color-999"}

      html = render_component(&GradientDecoration.gradient_blur/1, assigns)

      # Should default to blue (3B82F6)
      assert html =~ "stop-color=\"#3B82F6\""
    end
  end
end
