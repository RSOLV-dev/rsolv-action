defmodule RsolvWeb.Components.Marketing.CtaSimpleCenteredTest do
  use RsolvWeb.ConnCase, async: true
  import Phoenix.LiveViewTest

  alias RsolvWeb.Components.Marketing.CtaSimpleCentered

  describe "cta_simple_centered/1" do
    test "renders with required attributes only" do
      assigns = %{
        heading: "Get Started Today",
        description: "Join thousands of developers",
        primary_cta_text: "Sign Up",
        primary_cta_link: "/signup"
      }

      html = render_component(&CtaSimpleCentered.cta_simple_centered/1, assigns)

      assert html =~ "Get Started Today"
      assert html =~ "Join thousands of developers"
      assert html =~ "Sign Up"
      assert html =~ "href=\"/signup\""
    end

    test "renders with optional secondary CTA" do
      assigns = %{
        heading: "Test",
        description: "Test description",
        primary_cta_text: "Primary",
        primary_cta_link: "/primary",
        secondary_cta_text: "Learn More",
        secondary_cta_link: "/docs"
      }

      html = render_component(&CtaSimpleCentered.cta_simple_centered/1, assigns)

      assert html =~ "Learn More"
      assert html =~ "href=\"/docs\""
      assert html =~ "→"
    end

    test "does not render secondary CTA when not provided" do
      assigns = %{
        heading: "Test",
        description: "Test",
        primary_cta_text: "Primary",
        primary_cta_link: "/primary"
      }

      html = render_component(&CtaSimpleCentered.cta_simple_centered/1, assigns)

      # Should not have arrow for secondary CTA
      refute html =~ "→"
    end

    test "renders with optional image" do
      assigns = %{
        heading: "Test",
        description: "Test",
        primary_cta_text: "Test",
        primary_cta_link: "/test",
        image_url: "https://example.com/screenshot.png",
        image_alt: "Product screenshot"
      }

      html = render_component(&CtaSimpleCentered.cta_simple_centered/1, assigns)

      assert html =~ "src=\"https://example.com/screenshot.png\""
      assert html =~ "alt=\"Product screenshot\""
    end

    test "does not render image container when image not provided" do
      assigns = %{
        heading: "Test",
        description: "Test",
        primary_cta_text: "Test",
        primary_cta_link: "/test"
      }

      html = render_component(&CtaSimpleCentered.cta_simple_centered/1, assigns)

      # Should not have image container
      refute html =~ "relative mt-16 h-80"
    end

    test "uses default image alt text" do
      assigns = %{
        heading: "Test",
        description: "Test",
        primary_cta_text: "Test",
        primary_cta_link: "/test",
        image_url: "https://example.com/image.png"
      }

      html = render_component(&CtaSimpleCentered.cta_simple_centered/1, assigns)

      assert html =~ "alt=\"App screenshot\""
    end

    test "includes SVG radial gradient decoration" do
      assigns = %{
        heading: "Test",
        description: "Test",
        primary_cta_text: "Test",
        primary_cta_link: "/test"
      }

      html = render_component(&CtaSimpleCentered.cta_simple_centered/1, assigns)

      assert html =~ "<svg"
      assert html =~ "viewBox=\"0 0 1024 1024\""
      assert html =~ "<radialGradient"
      assert html =~ "id=\"gradient-decoration\""
      assert html =~ "stop-color=\"#3B82F6\""
      assert html =~ "stop-color=\"#10B981\""
    end

    test "has dark background panel" do
      assigns = %{
        heading: "Test",
        description: "Test",
        primary_cta_text: "Test",
        primary_cta_link: "/test"
      }

      html = render_component(&CtaSimpleCentered.cta_simple_centered/1, assigns)

      assert html =~ "bg-gray-900"
      assert html =~ "rounded-3xl"
      assert html =~ "shadow-2xl"
    end

    test "adjusts text alignment with and without image" do
      # Without image - should be centered
      assigns_no_image = %{
        heading: "Test",
        description: "Test",
        primary_cta_text: "Test",
        primary_cta_link: "/test"
      }

      html_no_image =
        render_component(&CtaSimpleCentered.cta_simple_centered/1, assigns_no_image)

      # Content should be centered when no image
      assert html_no_image =~ "text-center"

      # With image - should be left-aligned on large screens
      assigns_with_image = %{
        heading: "Test",
        description: "Test",
        primary_cta_text: "Test",
        primary_cta_link: "/test",
        image_url: "/test.png"
      }

      html_with_image =
        render_component(&CtaSimpleCentered.cta_simple_centered/1, assigns_with_image)

      # Content should be left-aligned on large screens when image present
      assert html_with_image =~ "lg:text-left"
    end

    test "includes dark mode classes" do
      assigns = %{
        heading: "Test",
        description: "Test",
        primary_cta_text: "Test",
        primary_cta_link: "/test"
      }

      html = render_component(&CtaSimpleCentered.cta_simple_centered/1, assigns)

      assert html =~ "dark:bg-gray-900"
      assert html =~ "text-white"
      assert html =~ "text-gray-300"
    end

    test "applies custom CSS class" do
      assigns = %{
        heading: "Test",
        description: "Test",
        primary_cta_text: "Test",
        primary_cta_link: "/test",
        class: "my-custom-cta"
      }

      html = render_component(&CtaSimpleCentered.cta_simple_centered/1, assigns)

      assert html =~ "my-custom-cta"
    end

    test "uses semantic HTML structure" do
      assigns = %{
        heading: "Call to Action",
        description: "Description text",
        primary_cta_text: "CTA",
        primary_cta_link: "/link"
      }

      html = render_component(&CtaSimpleCentered.cta_simple_centered/1, assigns)

      # Should use h2 for heading
      assert html =~ "<h2"
      assert html =~ "Call to Action"
      assert html =~ "</h2>"

      # Should use p for description
      assert html =~ "<p"
      assert html =~ "Description text"
      assert html =~ "</p>"
    end

    test "has responsive layout classes" do
      assigns = %{
        heading: "Test",
        description: "Test",
        primary_cta_text: "Test",
        primary_cta_link: "/test"
      }

      html = render_component(&CtaSimpleCentered.cta_simple_centered/1, assigns)

      # Responsive padding (normalized for better visual balance)
      assert html =~ "py-16"
      assert html =~ "sm:py-24"

      # Responsive flex layout
      assert html =~ "lg:flex"
      assert html =~ "lg:gap-x-20"
    end

    test "primary CTA has white background on dark panel" do
      assigns = %{
        heading: "Test",
        description: "Test",
        primary_cta_text: "Get Started",
        primary_cta_link: "/signup"
      }

      html = render_component(&CtaSimpleCentered.cta_simple_centered/1, assigns)

      # White button on dark background for contrast
      assert html =~ "bg-white"
      assert html =~ "text-gray-900"
      assert html =~ "hover:bg-gray-100"
    end

    test "includes accessibility attributes" do
      assigns = %{
        heading: "Test",
        description: "Test",
        primary_cta_text: "Test",
        primary_cta_link: "/test"
      }

      html = render_component(&CtaSimpleCentered.cta_simple_centered/1, assigns)

      # Decorative elements hidden from screen readers
      assert html =~ "aria-hidden=\"true\""

      # Focus visible styles for accessibility
      assert html =~ "focus-visible:outline"
    end

    test "adjusts button alignment with and without image" do
      # Without image
      assigns_no_image = %{
        heading: "Test",
        description: "Test",
        primary_cta_text: "Test",
        primary_cta_link: "/test"
      }

      html_no_image =
        render_component(&CtaSimpleCentered.cta_simple_centered/1, assigns_no_image)

      assert html_no_image =~ "justify-center"

      # With image
      assigns_with_image = %{
        heading: "Test",
        description: "Test",
        primary_cta_text: "Test",
        primary_cta_link: "/test",
        image_url: "/test.png"
      }

      html_with_image =
        render_component(&CtaSimpleCentered.cta_simple_centered/1, assigns_with_image)

      assert html_with_image =~ "justify-center lg:justify-start"
    end
  end
end
