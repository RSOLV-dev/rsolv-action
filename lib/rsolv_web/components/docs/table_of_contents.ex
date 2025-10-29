defmodule RsolvWeb.Components.Docs.TableOfContents do
  use Phoenix.Component

  @doc """
  Renders a table of contents component for documentation pages.

  The TOC can be:
  1. Manually provided as a list of headings
  2. Auto-generated from page content using JavaScript (client-side)

  For auto-generation, the component uses JavaScript to scan the page for
  h2 and h3 elements and build the TOC dynamically.

  ## Examples

      <!-- Auto-generated TOC -->
      <.table_of_contents container_id="doc-content" />

      <!-- Manual TOC -->
      <.table_of_contents headings={[
        %{id: "installation", title: "Installation", level: 2},
        %{id: "setup", title: "Setup", level: 3}
      ]} />

  ## Attributes

  - `container_id` - ID of the container to scan for headings (for auto-generation)
  - `headings` - Manual list of headings (overrides auto-generation)
  - `title` - Title for the TOC (default: "On this page")
  - `class` - Additional CSS classes
  """
  attr :container_id, :string, default: "doc-content"
  attr :headings, :list, default: nil
  attr :title, :string, default: "On this page"
  attr :class, :string, default: ""

  def table_of_contents(assigns) do
    ~H"""
    <nav
      class={[
        "sticky top-8 w-64 flex-shrink-0",
        @class
      ]}
      aria-label="Table of contents"
      id="toc-nav"
    >
      <div class="text-sm">
        <h2 class="mb-4 text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
          {@title}
        </h2>

        <%= if @headings do %>
          <!-- Manual headings provided -->
          <ul class="space-y-2" id="toc-list">
            <%= for heading <- @headings do %>
              <li class={heading.level == 3 && "ml-4"}>
                <a
                  href={"##{heading.id}"}
                  class="block py-1 text-slate-600 dark:text-slate-400 hover:text-blue-600 dark:hover:text-blue-400 transition-colors"
                  data-toc-link={heading.id}
                >
                  {heading.title}
                </a>
              </li>
            <% end %>
          </ul>
        <% else %>
          <!-- Auto-generated TOC -->
          <ul class="space-y-2" id="toc-list" data-toc-container={@container_id}>
            <!-- Will be populated by JavaScript -->
          </ul>
        <% end %>
      </div>
    </nav>

    <%= unless @headings do %>
      <script>
        // Auto-generate table of contents
        (function() {
          const tocList = document.getElementById('toc-list');
          const containerId = tocList.dataset.tocContainer;
          const container = document.getElementById(containerId);

          if (!container) return;

          // Find all h2 and h3 headings
          const headings = container.querySelectorAll('h2[id], h3[id]');

          headings.forEach((heading) => {
            const level = parseInt(heading.tagName[1]);
            const id = heading.id;
            const text = heading.textContent;

            const li = document.createElement('li');
            if (level === 3) {
              li.className = 'ml-4';
            }

            const a = document.createElement('a');
            a.href = `#${id}`;
            a.className = 'block py-1 text-slate-600 dark:text-slate-400 hover:text-blue-600 dark:hover:text-blue-400 transition-colors';
            a.setAttribute('data-toc-link', id);
            a.textContent = text;

            li.appendChild(a);
            tocList.appendChild(li);
          });

          // Highlight current section on scroll
          const observer = new IntersectionObserver(
            (entries) => {
              entries.forEach((entry) => {
                const id = entry.target.id;
                const link = document.querySelector(`[data-toc-link="${id}"]`);

                if (link) {
                  if (entry.isIntersecting) {
                    // Remove active class from all links
                    document.querySelectorAll('[data-toc-link]').forEach((l) => {
                      l.classList.remove('text-blue-600', 'dark:text-blue-400', 'font-medium');
                      l.classList.add('text-slate-600', 'dark:text-slate-400');
                    });

                    // Add active class to current link
                    link.classList.remove('text-slate-600', 'dark:text-slate-400');
                    link.classList.add('text-blue-600', 'dark:text-blue-400', 'font-medium');
                  }
                }
              });
            },
            {
              rootMargin: '-80px 0px -80% 0px'
            }
          );

          // Observe all headings
          headings.forEach((heading) => observer.observe(heading));
        })();
      </script>
    <% end %>
    """
  end
end
