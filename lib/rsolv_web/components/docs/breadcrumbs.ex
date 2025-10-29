defmodule RsolvWeb.Components.Docs.Breadcrumbs do
  use Phoenix.Component

  alias RsolvWeb.Components.Docs.Navigation

  @doc """
  Renders breadcrumb navigation for documentation pages.

  Automatically generates breadcrumbs based on the current path using
  the navigation structure defined in `RsolvWeb.Components.Docs.Navigation`.

  ## Examples

      <.breadcrumbs current_path="/docs/installation" />
      <.breadcrumbs current_path={@current_path} class="mb-4" />

  ## Attributes

  - `current_path` (required) - The current page path
  - `class` (optional) - Additional CSS classes
  """
  attr :current_path, :string, required: true
  attr :class, :string, default: ""

  def breadcrumbs(assigns) do
    assigns = assign(assigns, :crumbs, Navigation.breadcrumbs(assigns.current_path))

    ~H"""
    <nav aria-label="Breadcrumb" class={["flex items-center space-x-2 text-sm", @class]}>
      <%= for {crumb, index} <- Enum.with_index(@crumbs) do %>
        <%= if index > 0 do %>
          <svg
            class="h-4 w-4 flex-shrink-0 text-slate-400 dark:text-slate-600"
            fill="currentColor"
            viewBox="0 0 20 20"
          >
            <path
              fill-rule="evenodd"
              d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z"
              clip-rule="evenodd"
            />
          </svg>
        <% end %>

        <%= if index == length(@crumbs) - 1 do %>
          <span
            class="font-medium text-slate-900 dark:text-white"
            aria-current="page"
          >
            {crumb.title}
          </span>
        <% else %>
          <a
            href={crumb.href}
            class="font-medium text-slate-600 dark:text-slate-400 hover:text-blue-600 dark:hover:text-blue-400 transition-colors"
          >
            {crumb.title}
          </a>
        <% end %>
      <% end %>
    </nav>
    """
  end
end
