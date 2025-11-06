defmodule RsolvWeb.Components.Marketing.IconsTest do
  use ExUnit.Case, async: true

  alias RsolvWeb.Components.Marketing.Icons

  describe "checkmark/1" do
    test "renders with default options" do
      svg = Icons.checkmark()

      assert svg =~ "<svg"
      assert svg =~ "viewBox=\"0 0 20 20\""
      assert svg =~ "fill=\"currentColor\""
      assert svg =~ "aria-hidden=\"true\""
      assert svg =~ "h-6 w-5"
      assert svg =~ "text-blue-600"
      assert svg =~ "flex-none"
    end

    test "accepts custom color" do
      svg = Icons.checkmark(color: "text-green-600")

      assert svg =~ "text-green-600"
      refute svg =~ "text-blue-600"
    end

    test "accepts custom size" do
      svg = Icons.checkmark(size: "h-8 w-6")

      assert svg =~ "h-8 w-6"
      refute svg =~ "h-6 w-5"
    end

    test "accepts extra classes" do
      svg = Icons.checkmark(extra_classes: "custom-class")

      assert svg =~ "custom-class"
    end

    test "includes checkmark path" do
      svg = Icons.checkmark()

      assert svg =~ "<path"
      assert svg =~ "d=\"M16.704 4.153"
      assert svg =~ "clip-rule=\"evenodd\""
      assert svg =~ "fill-rule=\"evenodd\""
    end
  end

  describe "checkmark_circle/1" do
    test "renders with default options" do
      svg = Icons.checkmark_circle()

      assert svg =~ "<svg"
      assert svg =~ "viewBox=\"0 0 24 24\""
      assert svg =~ "fill=\"none\""
      assert svg =~ "stroke=\"currentColor\""
      assert svg =~ "stroke-width=\"1.5\""
      assert svg =~ "size-6"
      assert svg =~ "text-white"
    end

    test "accepts custom color" do
      svg = Icons.checkmark_circle(color: "text-blue-600")

      assert svg =~ "text-blue-600"
      refute svg =~ "text-white"
    end

    test "accepts custom size" do
      svg = Icons.checkmark_circle(size: "size-8")

      assert svg =~ "size-8"
      refute svg =~ "size-6"
    end

    test "accepts custom stroke width" do
      svg = Icons.checkmark_circle(stroke_width: "2")

      assert svg =~ "stroke-width=\"2\""
      refute svg =~ "stroke-width=\"1.5\""
    end

    test "includes checkmark circle path" do
      svg = Icons.checkmark_circle()

      assert svg =~ "<path"
      assert svg =~ "stroke-linecap=\"round\""
      assert svg =~ "stroke-linejoin=\"round\""
      assert svg =~ "M9 12.75 11.25 15 15 9.75M21 12"
    end
  end

  describe "lock/1" do
    test "renders with default options" do
      svg = Icons.lock()

      assert svg =~ "<svg"
      assert svg =~ "viewBox=\"0 0 24 24\""
      assert svg =~ "text-white"
      assert svg =~ "size-6"
    end

    test "includes padlock path" do
      svg = Icons.lock()

      assert svg =~ "M16.5 10.5V6.75a4.5"
      assert svg =~ "m-.75 11.25h10.5"
    end
  end

  describe "lightning/1" do
    test "renders with default options" do
      svg = Icons.lightning()

      assert svg =~ "<svg"
      assert svg =~ "viewBox=\"0 0 24 24\""
      assert svg =~ "text-white"
    end

    test "includes lightning bolt path" do
      svg = Icons.lightning()

      assert svg =~ "M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75"
    end
  end

  describe "chart_up/1" do
    test "renders with default options" do
      svg = Icons.chart_up()

      assert svg =~ "<svg"
      assert svg =~ "viewBox=\"0 0 24 24\""
      assert svg =~ "text-white"
    end

    test "includes ascending chart path" do
      svg = Icons.chart_up()

      assert svg =~ "M2.25 18 9 11.25l4.306 4.306"
      assert svg =~ "m0 0-5.94-2.281m5.94 2.28-2.28 5.941"
    end
  end

  describe "shield/1" do
    test "renders with default options" do
      svg = Icons.shield()

      assert svg =~ "<svg"
      assert svg =~ "viewBox=\"0 0 24 24\""
      assert svg =~ "text-white"
    end

    test "includes shield with checkmark path" do
      svg = Icons.shield()

      assert svg =~ "M9 12.75 11.25 15 15 9.75"
      assert svg =~ "c0 5.592 3.824 10.29 9 11.623"
    end
  end

  describe "code/1" do
    test "renders with default options" do
      svg = Icons.code()

      assert svg =~ "<svg"
      assert svg =~ "viewBox=\"0 0 24 24\""
      assert svg =~ "text-white"
    end

    test "includes code brackets path" do
      svg = Icons.code()

      assert svg =~ "M17.25 6.75 22.5 12l-5.25 5.25"
      assert svg =~ "m-10.5 0L1.5 12l5.25-5.25"
      assert svg =~ "m7.5-3-4.5 16.5"
    end
  end

  describe "rocket/1" do
    test "renders with default options" do
      svg = Icons.rocket()

      assert svg =~ "<svg"
      assert svg =~ "viewBox=\"0 0 24 24\""
      assert svg =~ "text-white"
    end

    test "includes rocket path" do
      svg = Icons.rocket()

      assert svg =~ "M15.59 14.37a6 6 0 0 1-5.84 7.38"
      assert svg =~ "M16.5 9a1.5 1.5 0 1 1-3 0"
    end
  end

  describe "all icons" do
    test "all icons return valid SVG strings" do
      icons = [
        Icons.checkmark(),
        Icons.checkmark_circle(),
        Icons.lock(),
        Icons.lightning(),
        Icons.chart_up(),
        Icons.shield(),
        Icons.code(),
        Icons.rocket()
      ]

      for svg <- icons do
        assert is_binary(svg)
        assert svg =~ "<svg"
        assert svg =~ "</svg>"
        assert svg =~ "aria-hidden=\"true\""
      end
    end

    test "all icons support custom colors" do
      custom_color = "text-custom-color"

      icons = [
        Icons.checkmark(color: custom_color),
        Icons.checkmark_circle(color: custom_color),
        Icons.lock(color: custom_color),
        Icons.lightning(color: custom_color),
        Icons.chart_up(color: custom_color),
        Icons.shield(color: custom_color),
        Icons.code(color: custom_color),
        Icons.rocket(color: custom_color)
      ]

      for svg <- icons do
        assert svg =~ custom_color
      end
    end
  end
end
