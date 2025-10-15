defmodule RsolvWeb.Components.Header do
  use Phoenix.Component
  use RsolvWeb, :verified_routes
  import RsolvWeb.Components.ThemeToggle

  def header(assigns) do
    # Determine if we're on the homepage
    is_homepage = assigns[:current_path] == "/"

    # Set header styling based on page
    header_class =
      if is_homepage do
        "fixed top-0 left-0 right-0 z-50 transition-all duration-300 bg-white/80 dark:bg-gray-900/80 backdrop-blur-sm"
      else
        "sticky top-0 z-50 bg-white dark:bg-gray-900 shadow-sm border-b border-gray-200 dark:border-gray-800"
      end

    text_color =
      if is_homepage,
        do: "text-gray-900 dark:text-white",
        else: "text-gray-900 dark:text-gray-100"

    link_color =
      if is_homepage,
        do: "text-gray-700 dark:text-white/90 hover:text-gray-900 dark:hover:text-white",
        else: "text-gray-700 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white"

    button_class =
      if is_homepage do
        "bg-brand-blue dark:bg-white text-white dark:text-brand-blue font-medium py-2 px-6 rounded-md hover:bg-blue-600 dark:hover:bg-gray-100 transition-colors"
      else
        "bg-indigo-600 dark:bg-brand-blue text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-indigo-700 dark:hover:bg-blue-600"
      end

    assigns =
      assigns
      |> assign(:is_homepage, is_homepage)
      |> assign(:header_class, header_class)
      |> assign(:text_color, text_color)
      |> assign(:link_color, link_color)
      |> assign(:button_class, button_class)
      |> assign_new(:show_blog_link, fn -> FunWithFlags.enabled?(:blog) end)
      |> assign_new(:mobile_menu_open, fn -> false end)
      |> assign_new(:socket, fn -> nil end)

    ~H"""
    <header class={@header_class}>
      <div class="container mx-auto px-4 sm:px-6 lg:px-8">
        <div class="flex items-center justify-between py-4 text-sm">
          <div class="flex items-center gap-4">
            <a href="/" class="flex items-center">
              <img
                src={~p"/images/rsolv_logo_transparent.png"}
                width="100"
                alt="RSOLV - Automatic Security Detection"
                id="header-logo"
              />
            </a>
          </div>
          <nav class="hidden md:flex items-center gap-8">
            <%= if @is_homepage do %>
              <a href="#features" class={"font-medium #{@link_color} transition-colors"}>Features</a>
              <a href="#pricing" class={"font-medium #{@link_color} transition-colors"}>Pricing</a>
              <a href="#faq" class={"font-medium #{@link_color} transition-colors"}>FAQ</a>
            <% else %>
              <a href="/" class={"font-medium #{@link_color} transition-colors"}>Home</a>
              <a href="/#features" class={"font-medium #{@link_color} transition-colors"}>Features</a>
              <a href="/#pricing" class={"font-medium #{@link_color} transition-colors"}>Pricing</a>
            <% end %>
            <%= if @show_blog_link do %>
              <a href="/blog" class={"font-medium #{@link_color} transition-colors"}>Blog</a>
            <% end %>
            <a href="/feedback" class={"font-medium #{@link_color} transition-colors"}>Feedback</a>
            <.theme_toggle class="ml-2" variant={if @is_homepage, do: "homepage", else: "default"} />
            <a href="/#early-access" class={@button_class}>
              Get Early Access <span aria-hidden="true">&rarr;</span>
            </a>
          </nav>
          <!-- Mobile menu button -->
          <div class="md:hidden flex items-center gap-2">
            <.theme_toggle variant={if @is_homepage, do: "homepage", else: "default"} />
            <a href="/#early-access" class={"#{@button_class} text-sm px-3 py-1.5"}>
              Get Early Access
            </a>
            <button
              type="button"
              phx-click={@socket && "toggle_mobile_menu"}
              class={"mobile-menu-button inline-flex items-center justify-center p-2 rounded-md #{@link_color} hover:bg-white/10 dark:hover:bg-dark-800/50 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-white dark:focus:ring-dark-400"}
              aria-controls="mobile-menu"
              aria-expanded={@mobile_menu_open}
              id="mobile-menu-button"
            >
              <span class="sr-only">Open main menu</span>
              <!-- Hamburger icon -->
              <svg
                class="block h-6 w-6"
                fill="none"
                viewBox="0 0 24 24"
                stroke-width="1.5"
                stroke="currentColor"
                aria-hidden="true"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25h16.5"
                />
              </svg>
            </button>
          </div>
        </div>
        <!-- Mobile menu -->
        <div class={"md:hidden #{if @mobile_menu_open, do: "", else: "hidden"}"} id="mobile-menu">
          <div class="px-2 pt-2 pb-3 space-y-1">
            <%= if @is_homepage do %>
              <a
                href="#features"
                phx-click={@socket && "close_mobile_menu"}
                class={"block px-3 py-2 rounded-md text-base font-medium #{@link_color}"}
              >
                Features
              </a>
              <a
                href="#pricing"
                phx-click={@socket && "close_mobile_menu"}
                class={"block px-3 py-2 rounded-md text-base font-medium #{@link_color}"}
              >
                Pricing
              </a>
              <a
                href="#faq"
                phx-click={@socket && "close_mobile_menu"}
                class={"block px-3 py-2 rounded-md text-base font-medium #{@link_color}"}
              >
                FAQ
              </a>
            <% else %>
              <a
                href="/"
                phx-click={@socket && "close_mobile_menu"}
                class={"block px-3 py-2 rounded-md text-base font-medium #{@link_color}"}
              >
                Home
              </a>
              <a
                href="/#features"
                phx-click={@socket && "close_mobile_menu"}
                class={"block px-3 py-2 rounded-md text-base font-medium #{@link_color}"}
              >
                Features
              </a>
              <a
                href="/#pricing"
                phx-click={@socket && "close_mobile_menu"}
                class={"block px-3 py-2 rounded-md text-base font-medium #{@link_color}"}
              >
                Pricing
              </a>
            <% end %>
            <%= if @show_blog_link do %>
              <a
                href="/blog"
                phx-click={@socket && "close_mobile_menu"}
                class={"block px-3 py-2 rounded-md text-base font-medium #{@link_color}"}
              >
                Blog
              </a>
            <% end %>
            <a
              href="/feedback"
              phx-click={@socket && "close_mobile_menu"}
              class={"block px-3 py-2 rounded-md text-base font-medium #{@link_color}"}
            >
              Feedback
            </a>
          </div>
        </div>
      </div>
    </header>
    """
  end
end
