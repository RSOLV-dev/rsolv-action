defmodule RsolvWeb.Components.Marketing.HeroSimpleCenteredTest do
  use RsolvWeb.ConnCase, async: true
  import Phoenix.LiveViewTest

  alias RsolvWeb.Components.Marketing.HeroSimpleCentered

  describe "hero_simple_centered/1" do
    test "renders with required attributes only" do
      assigns = %{
        heading: "Test Heading",
        subheading: "Test Subheading",
        primary_cta_text: "Get Started",
        primary_cta_link: "/signup"
      }

      html = render_component(&HeroSimpleCentered.hero_simple_centered/1, assigns)

      assert html =~ "Test Heading"
      assert html =~ "Test Subheading"
      assert html =~ "Get Started"
      assert html =~ "href=\"/signup\""
    end

    test "renders with optional secondary CTA" do
      assigns = %{
        heading: "Test",
        subheading: "Test",
        primary_cta_text: "Primary",
        primary_cta_link: "/primary",
        secondary_cta_text: "Learn More",
        secondary_cta_link: "/docs"
      }

      html = render_component(&HeroSimpleCentered.hero_simple_centered/1, assigns)

      assert html =~ "Learn More"
      assert html =~ "href=\"/docs\""
      assert html =~ "→"
    end

    test "does not render secondary CTA when not provided" do
      assigns = %{
        heading: "Test",
        subheading: "Test",
        primary_cta_text: "Primary",
        primary_cta_link: "/primary"
      }

      html = render_component(&HeroSimpleCentered.hero_simple_centered/1, assigns)

      # Should only have one CTA
      refute html =~ "→"
    end

    test "renders with optional announcement badge" do
      assigns = %{
        heading: "Test",
        subheading: "Test",
        primary_cta_text: "Test",
        primary_cta_link: "/test",
        announcement_text: "New Feature Launched",
        announcement_link: "/blog/new-feature",
        announcement_link_text: "Read more"
      }

      html = render_component(&HeroSimpleCentered.hero_simple_centered/1, assigns)

      assert html =~ "New Feature Launched"
      assert html =~ "href=\"/blog/new-feature\""
      assert html =~ "Read more"
    end

    test "renders announcement with default link text" do
      assigns = %{
        heading: "Test",
        subheading: "Test",
        primary_cta_text: "Test",
        primary_cta_link: "/test",
        announcement_text: "Announcement",
        announcement_link: "/blog/post"
      }

      html = render_component(&HeroSimpleCentered.hero_simple_centered/1, assigns)

      assert html =~ "Announcement"
      assert html =~ "Read more"
    end

    test "does not render announcement when not provided" do
      assigns = %{
        heading: "Test",
        subheading: "Test",
        primary_cta_text: "Test",
        primary_cta_link: "/test"
      }

      html = render_component(&HeroSimpleCentered.hero_simple_centered/1, assigns)

      # Should not have announcement badge container
      refute html =~ "sm:mb-8 sm:flex sm:justify-center"
    end

    test "includes gradient decoration elements" do
      assigns = %{
        heading: "Test",
        subheading: "Test",
        primary_cta_text: "Test",
        primary_cta_link: "/test"
      }

      html = render_component(&HeroSimpleCentered.hero_simple_centered/1, assigns)

      # Top gradient
      assert html =~ "bg-gradient-to-tr from-blue-600 to-emerald-600"
      assert html =~ "-top-40"

      # Bottom gradient
      assert html =~ "top-[calc(100%-13rem)]"

      # Aria-hidden for decorative elements
      assert html =~ "aria-hidden=\"true\""
    end

    test "includes dark mode classes" do
      assigns = %{
        heading: "Test",
        subheading: "Test",
        primary_cta_text: "Test",
        primary_cta_link: "/test"
      }

      html = render_component(&HeroSimpleCentered.hero_simple_centered/1, assigns)

      assert html =~ "dark:bg-gray-900"
      assert html =~ "dark:text-white"
      assert html =~ "dark:text-gray-400"
    end

    test "applies custom CSS class" do
      assigns = %{
        heading: "Test",
        subheading: "Test",
        primary_cta_text: "Test",
        primary_cta_link: "/test",
        class: "my-custom-hero-class"
      }

      html = render_component(&HeroSimpleCentered.hero_simple_centered/1, assigns)

      assert html =~ "my-custom-hero-class"
    end

    test "includes responsive design classes" do
      assigns = %{
        heading: "Test",
        subheading: "Test",
        primary_cta_text: "Test",
        primary_cta_link: "/test"
      }

      html = render_component(&HeroSimpleCentered.hero_simple_centered/1, assigns)

      # Responsive text sizing
      assert html =~ "text-5xl"
      assert html =~ "sm:text-7xl"

      # Responsive spacing
      assert html =~ "py-32"
      assert html =~ "sm:py-48"
      assert html =~ "lg:py-56"
    end

    test "uses semantic HTML structure" do
      assigns = %{
        heading: "Main Heading",
        subheading: "Subheading Text",
        primary_cta_text: "CTA",
        primary_cta_link: "/link"
      }

      html = render_component(&HeroSimpleCentered.hero_simple_centered/1, assigns)

      # Should use h1 for heading
      assert html =~ "<h1"
      assert html =~ "Main Heading"
      assert html =~ "</h1>"

      # Should use p for subheading
      assert html =~ "<p"
      assert html =~ "Subheading Text"
      assert html =~ "</p>"
    end

    test "primary CTA has proper focus styles for accessibility" do
      assigns = %{
        heading: "Test",
        subheading: "Test",
        primary_cta_text: "Click Me",
        primary_cta_link: "/test"
      }

      html = render_component(&HeroSimpleCentered.hero_simple_centered/1, assigns)

      assert html =~ "focus-visible:outline"
      assert html =~ "focus-visible:outline-2"
      assert html =~ "focus-visible:outline-offset-2"
    end
  end
end
