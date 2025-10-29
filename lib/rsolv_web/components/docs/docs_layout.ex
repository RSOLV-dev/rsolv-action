defmodule RsolvWeb.Components.Docs.DocsLayout do
  use Phoenix.Component

  alias RsolvWeb.Components.Docs.{Breadcrumbs, Navigation, SidebarNav, TableOfContents}
  alias RsolvWeb.Components.ThemeToggle

  @doc """
  Renders the complete documentation page layout with sidebar navigation,
  breadcrumbs, table of contents, and next/previous page navigation.

  This is the main layout component that wraps all documentation pages.

  ## Examples

      <.docs_layout current_path="/docs/installation">
        <h1 id="installation">Installation</h1>
        <p>Content here...</p>
      </.docs_layout>

      <.docs_layout current_path={@current_path} show_toc={false}>
        Content without TOC
      </.docs_layout>

  ## Attributes

  - `current_path` (required) - The current page path
  - `show_toc` - Show table of contents (default: true)
  - `toc_headings` - Manual TOC headings (optional, auto-generated if not provided)
  - `show_breadcrumbs` - Show breadcrumb navigation (default: true)
  - `show_nav_footer` - Show next/previous navigation (default: true)
  - `class` - Additional CSS classes for content area
  """
  attr :current_path, :string, required: true
  attr :show_toc, :boolean, default: true
  attr :toc_headings, :list, default: nil
  attr :show_breadcrumbs, :boolean, default: true
  attr :show_nav_footer, :boolean, default: true
  attr :class, :string, default: ""
  slot :inner_block, required: true

  def docs_layout(assigns) do
    {prev_page, next_page} = Navigation.find_adjacent_pages(assigns.current_path)
    assigns = assign(assigns, prev_page: prev_page, next_page: next_page)

    ~H"""
    <div class="min-h-screen bg-white dark:bg-slate-900">
      <!-- Mobile menu button -->
      <div class="lg:hidden fixed top-4 left-4 z-50">
        <button
          type="button"
          class="p-2 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 shadow-sm"
          onclick="toggleMobileNav()"
          aria-label="Toggle navigation"
        >
          <svg
            class="w-6 h-6 text-slate-700 dark:text-slate-300"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="2"
              d="M4 6h16M4 12h16M4 18h16"
            />
          </svg>
        </button>
      </div>
      
    <!-- Mobile overlay -->
      <div
        id="mobile-nav-overlay"
        class="hidden fixed inset-0 bg-slate-900/50 z-40 lg:hidden"
        onclick="toggleMobileNav()"
      >
      </div>

      <div class="flex">
        <!-- Sidebar navigation -->
        <div id="mobile-nav">
          <SidebarNav.sidebar_nav current_path={@current_path} />
        </div>
        
    <!-- Main content area -->
        <div class="flex-1 flex">
          <!-- Content -->
          <main class="flex-1 px-4 sm:px-6 lg:px-8 py-8 max-w-4xl">
            <!-- Top bar with breadcrumbs and theme toggle -->
            <%= if @show_breadcrumbs do %>
              <div class="mb-8 flex items-center justify-between">
                <Breadcrumbs.breadcrumbs current_path={@current_path} />
                <ThemeToggle.theme_toggle />
              </div>
            <% end %>
            
    <!-- Page content -->
            <article id="doc-content" class={["prose prose-slate dark:prose-invert", @class]}>
              {render_slot(@inner_block)}
            </article>
            
    <!-- Next/Previous navigation -->
            <%= if @show_nav_footer && (@prev_page || @next_page) do %>
              <nav
                class="mt-12 pt-8 border-t border-slate-200 dark:border-slate-700"
                aria-label="Page navigation"
              >
                <div class="grid grid-cols-2 gap-4">
                  <%= if @prev_page do %>
                    <a
                      href={@prev_page.href}
                      class="group flex flex-col p-4 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-blue-500 dark:hover:border-blue-500 transition-colors"
                    >
                      <span class="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1">
                        Previous
                      </span>
                      <span class="text-sm font-medium text-slate-900 dark:text-white group-hover:text-blue-600 dark:group-hover:text-blue-400">
                        {@prev_page.title}
                      </span>
                    </a>
                  <% else %>
                    <div></div>
                  <% end %>

                  <%= if @next_page do %>
                    <a
                      href={@next_page.href}
                      class="group flex flex-col p-4 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-blue-500 dark:hover:border-blue-500 transition-colors text-right"
                    >
                      <span class="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1">
                        Next
                      </span>
                      <span class="text-sm font-medium text-slate-900 dark:text-white group-hover:text-blue-600 dark:group-hover:text-blue-400">
                        {@next_page.title}
                      </span>
                    </a>
                  <% end %>
                </div>
              </nav>
            <% end %>
            
    <!-- Edit on GitHub link -->
            <div class="mt-8 pt-8 border-t border-slate-200 dark:border-slate-700">
              <a
                href="https://github.com/RSOLV-dev/rsolv-action/tree/main/docs"
                target="_blank"
                rel="noopener noreferrer"
                class="inline-flex items-center text-sm text-slate-600 dark:text-slate-400 hover:text-blue-600 dark:hover:text-blue-400 transition-colors"
              >
                <svg class="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
                </svg>
                Edit this page on GitHub
              </a>
            </div>
          </main>
          
    <!-- Table of contents (desktop only) -->
          <%= if @show_toc do %>
            <aside class="hidden xl:block w-64 px-4 py-8">
              <TableOfContents.table_of_contents
                container_id="doc-content"
                headings={@toc_headings}
              />
            </aside>
          <% end %>
        </div>
      </div>
    </div>

    <script>
      // Mobile navigation toggle
      window.toggleMobileNav = function() {
        const nav = document.getElementById('mobile-nav');
        const overlay = document.getElementById('mobile-nav-overlay');

        nav.classList.toggle('hidden');
        overlay.classList.toggle('hidden');
      };

      // Close mobile nav when clicking a link
      document.addEventListener('DOMContentLoaded', () => {
        const mobileNav = document.getElementById('mobile-nav');
        if (mobileNav) {
          mobileNav.querySelectorAll('a').forEach((link) => {
            link.addEventListener('click', () => {
              toggleMobileNav();
            });
          });
        }
      });

      // Keyboard shortcuts
      document.addEventListener('keydown', (e) => {
        // Forward slash to focus search (if implemented)
        if (e.key === '/' && !e.ctrlKey && !e.metaKey && !e.altKey) {
          const activeElement = document.activeElement;
          if (activeElement && (activeElement.tagName === 'INPUT' || activeElement.tagName === 'TEXTAREA')) {
            return;
          }
          e.preventDefault();
          // Search functionality to be implemented
        }
      });
    </script>
    """
  end
end
