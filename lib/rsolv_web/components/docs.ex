defmodule RsolvWeb.Components.Docs do
  @moduledoc """
  Documentation site components for RSOLV.

  This module provides a collection of reusable components for building
  professional documentation pages with navigation, TOC, code blocks, and more.

  ## Components

  - `DocsLayout` - Main layout wrapper with sidebar and TOC
  - `SidebarNav` - Hierarchical navigation menu
  - `TableOfContents` - Auto-generated or manual TOC
  - `Breadcrumbs` - Breadcrumb navigation
  - `CodeBlock` - Syntax-highlighted code with copy functionality
  - `Callout` - Info/warning/error/success/note boxes

  ## Usage

  Import this module in your view or component:

      use RsolvWeb.Components.Docs

  This gives you access to all documentation components with the `Docs.*` namespace.

  ## Example

      defmodule MyApp.DocsHTML do
        use Phoenix.Component
        use RsolvWeb.Components.Docs

        def my_page(assigns) do
          ~H\"\"\"
          <Docs.DocsLayout.docs_layout current_path="/docs/example">
            <h1>My Documentation Page</h1>

            <Docs.Callout.callout variant="info">
              This is an informational callout.
            </Docs.Callout.callout>

            <Docs.CodeBlock.code_block language="elixir">
              defmodule Example do
                def hello, do: "world"
              end
            </Docs.CodeBlock.code_block>
          </Docs.DocsLayout.docs_layout>
          \"\"\"
        end
      end
  """

  defmacro __using__(_opts) do
    quote do
      import RsolvWeb.Components.Docs.Breadcrumbs
      import RsolvWeb.Components.Docs.Callout
      import RsolvWeb.Components.Docs.CodeBlock
      import RsolvWeb.Components.Docs.DocsLayout
      import RsolvWeb.Components.Docs.SidebarNav
      import RsolvWeb.Components.Docs.TableOfContents

      alias RsolvWeb.Components.Docs.Navigation
    end
  end
end
