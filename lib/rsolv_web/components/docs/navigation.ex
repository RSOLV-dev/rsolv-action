defmodule RsolvWeb.Components.Docs.Navigation do
  @moduledoc """
  Defines the documentation site navigation structure.

  This module provides the hierarchical navigation menu and helps determine
  active pages, breadcrumbs, and next/previous navigation.
  """

  @doc """
  Returns the complete navigation structure for the documentation site.

  Each section has:
  - `title`: Display name
  - `icon`: SVG path for the section icon
  - `pages`: List of pages in the section

  Each page has:
  - `title`: Display name
  - `href`: URL path
  - `description`: Short description (for cards/previews)
  """
  def navigation_tree do
    [
      %{
        title: "Getting Started",
        icon: "M13 10V3L4 14h7v7l9-11h-7z",
        pages: [
          %{
            title: "Introduction",
            href: "/docs",
            description: "Overview and key features of RSOLV"
          },
          %{
            title: "Installation",
            href: "/docs/installation",
            description: "Step-by-step installation guide"
          },
          %{
            title: "Getting Started",
            href: "/docs/getting-started",
            description: "Quick tutorial to run your first scan"
          }
        ]
      },
      %{
        title: "Configuration",
        icon:
          "M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z",
        pages: [
          %{
            title: "Configuration Options",
            href: "/docs/configuration",
            description: "Customize RSOLV behavior"
          },
          %{
            title: "Workflow Templates",
            href: "/docs/workflows",
            description: "Ready-to-use workflow examples"
          }
        ]
      },
      %{
        title: "Reference",
        icon:
          "M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253",
        pages: [
          %{
            title: "API Reference",
            href: "/docs/api-reference",
            description: "Complete API documentation"
          },
          %{
            title: "Troubleshooting",
            href: "/docs/troubleshooting",
            description: "Common issues and solutions"
          },
          %{
            title: "FAQ",
            href: "/docs/faq",
            description: "Frequently asked questions"
          }
        ]
      }
    ]
  end

  @doc """
  Returns a flat list of all pages for easier navigation operations.
  """
  def all_pages do
    navigation_tree()
    |> Enum.flat_map(fn section -> section.pages end)
  end

  @doc """
  Finds the next and previous pages for a given path.
  Returns `{previous_page, next_page}` or `{nil, next_page}` or `{previous_page, nil}`.
  """
  def find_adjacent_pages(current_path) do
    pages = all_pages()
    current_index = Enum.find_index(pages, fn page -> page.href == current_path end)

    case current_index do
      nil ->
        {nil, nil}

      0 ->
        {nil, Enum.at(pages, 1)}

      index when index == length(pages) - 1 ->
        {Enum.at(pages, index - 1), nil}

      index ->
        {Enum.at(pages, index - 1), Enum.at(pages, index + 1)}
    end
  end

  @doc """
  Builds breadcrumbs for a given page path.
  Always includes "Documentation" as the root.
  """
  def breadcrumbs(current_path) do
    home = %{title: "Documentation", href: "/docs"}

    if current_path == "/docs" do
      [home]
    else
      page = all_pages() |> Enum.find(fn p -> p.href == current_path end)

      case page do
        nil -> [home]
        page -> [home, page]
      end
    end
  end

  @doc """
  Determines if a page is the current page (for active state styling).
  """
  def current_page?(page_href, current_path) do
    page_href == current_path
  end
end
