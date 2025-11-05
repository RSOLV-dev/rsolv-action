defmodule RsolvWeb.Components.Marketing.FeaturesGrid2x2Test do
  use RsolvWeb.ConnCase, async: true
  import Phoenix.LiveViewTest

  alias RsolvWeb.Components.Marketing.FeaturesGrid2x2

  @sample_features [
    %{
      icon: ~S'<svg class="test-icon-1"><path /></svg>',
      title: "Feature One",
      description: "Description for feature one"
    },
    %{
      icon: ~S'<svg class="test-icon-2"><path /></svg>',
      title: "Feature Two",
      description: "Description for feature two"
    },
    %{
      icon: ~S'<svg class="test-icon-3"><path /></svg>',
      title: "Feature Three",
      description: "Description for feature three"
    },
    %{
      icon: ~S'<svg class="test-icon-4"><path /></svg>',
      title: "Feature Four",
      description: "Description for feature four"
    }
  ]

  describe "features_grid_2x2/1" do
    test "renders with required attributes" do
      assigns = %{
        heading: "Our Features",
        subheading: "Everything you need",
        features: @sample_features
      }

      html = render_component(&FeaturesGrid2x2.features_grid_2x2/1, assigns)

      assert html =~ "Our Features"
      assert html =~ "Everything you need"

      # All features should be present
      assert html =~ "Feature One"
      assert html =~ "Feature Two"
      assert html =~ "Feature Three"
      assert html =~ "Feature Four"
    end

    test "renders optional eyebrow text" do
      assigns = %{
        eyebrow: "Why Choose Us",
        heading: "Our Features",
        subheading: "Everything you need",
        features: @sample_features
      }

      html = render_component(&FeaturesGrid2x2.features_grid_2x2/1, assigns)

      assert html =~ "Why Choose Us"
    end

    test "does not render eyebrow when not provided" do
      assigns = %{
        heading: "Our Features",
        subheading: "Everything you need",
        features: @sample_features
      }

      html = render_component(&FeaturesGrid2x2.features_grid_2x2/1, assigns)

      # Should not have h2 with eyebrow styling
      refute html =~ "text-base/7 font-semibold text-blue-600"
    end

    test "renders all feature icons" do
      assigns = %{
        heading: "Features",
        subheading: "Test",
        features: @sample_features
      }

      html = render_component(&FeaturesGrid2x2.features_grid_2x2/1, assigns)

      assert html =~ "test-icon-1"
      assert html =~ "test-icon-2"
      assert html =~ "test-icon-3"
      assert html =~ "test-icon-4"
    end

    test "uses definition list for semantic HTML" do
      assigns = %{
        heading: "Features",
        subheading: "Test",
        features: @sample_features
      }

      html = render_component(&FeaturesGrid2x2.features_grid_2x2/1, assigns)

      # Should use dl/dt/dd for features
      assert html =~ "<dl"
      assert html =~ "<dt"
      assert html =~ "<dd"
    end

    test "applies 2x2 grid layout classes" do
      assigns = %{
        heading: "Features",
        subheading: "Test",
        features: @sample_features
      }

      html = render_component(&FeaturesGrid2x2.features_grid_2x2/1, assigns)

      # Grid layout
      assert html =~ "grid"
      assert html =~ "grid-cols-1"
      assert html =~ "lg:grid-cols-2"
      assert html =~ "gap-x-8"
      assert html =~ "gap-y-10"
    end

    test "includes dark mode classes" do
      assigns = %{
        heading: "Features",
        subheading: "Test",
        features: @sample_features
      }

      html = render_component(&FeaturesGrid2x2.features_grid_2x2/1, assigns)

      assert html =~ "dark:bg-gray-900"
      assert html =~ "dark:text-white"
      assert html =~ "dark:text-gray-300"
      assert html =~ "dark:text-gray-400"
    end

    test "applies custom CSS class" do
      assigns = %{
        heading: "Features",
        subheading: "Test",
        features: @sample_features,
        class: "custom-features-class"
      }

      html = render_component(&FeaturesGrid2x2.features_grid_2x2/1, assigns)

      assert html =~ "custom-features-class"
    end

    test "centers heading and subheading" do
      assigns = %{
        heading: "Features",
        subheading: "Test",
        features: @sample_features
      }

      html = render_component(&FeaturesGrid2x2.features_grid_2x2/1, assigns)

      assert html =~ "lg:text-center"
      assert html =~ "text-center"
    end

    test "uses responsive typography" do
      assigns = %{
        heading: "Features",
        subheading: "Test",
        features: @sample_features
      }

      html = render_component(&FeaturesGrid2x2.features_grid_2x2/1, assigns)

      # Heading responsive sizing
      assert html =~ "text-4xl"
      assert html =~ "sm:text-5xl"

      # Subheading responsive sizing
      assert html =~ "text-lg/8"
    end

    test "positions feature icons with absolute positioning" do
      assigns = %{
        heading: "Features",
        subheading: "Test",
        features: @sample_features
      }

      html = render_component(&FeaturesGrid2x2.features_grid_2x2/1, assigns)

      # Icon container
      assert html =~ "absolute top-0 left-0"
      assert html =~ "flex size-10"
      assert html =~ "rounded-lg bg-blue-600"
    end

    test "handles empty features list gracefully" do
      assigns = %{
        heading: "Features",
        subheading: "Test",
        features: []
      }

      html = render_component(&FeaturesGrid2x2.features_grid_2x2/1, assigns)

      # Should still render heading
      assert html =~ "Features"
      # But no feature items
      refute html =~ "<dt"
    end

    test "renders with exactly 4 features (2x2 grid)" do
      assigns = %{
        heading: "Features",
        subheading: "Test",
        features: @sample_features
      }

      html = render_component(&FeaturesGrid2x2.features_grid_2x2/1, assigns)

      # Count dt elements (one per feature)
      dt_count = html |> String.split("<dt") |> length() |> Kernel.-(1)
      assert dt_count == 4
    end

    test "includes proper spacing for feature descriptions" do
      assigns = %{
        heading: "Features",
        subheading: "Test",
        features: @sample_features
      }

      html = render_component(&FeaturesGrid2x2.features_grid_2x2/1, assigns)

      # Description spacing
      assert html =~ "mt-2 text-base/7"
      # Feature spacing from icon
      assert html =~ "pl-16"
    end
  end
end
