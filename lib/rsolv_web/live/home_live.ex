defmodule RsolvWeb.HomeLive do
  use RsolvWeb, :live_view
  require Logger

  @impl true
  def mount(params, session, socket) do
    socket = 
      socket
      |> assign(:email, "")
      |> assign(:company, "")
      |> assign(:errors, %{})
      |> assign(:submitting, false)
      |> assign(:mobile_menu_open, false)
      |> assign(:csrf_token, session["_csrf_token"])
      |> assign(:utm_source, params["utm_source"])
      |> assign(:utm_medium, params["utm_medium"])
      |> assign(:utm_campaign, params["utm_campaign"])
      |> assign(:utm_term, params["utm_term"])
      |> assign(:utm_content, params["utm_content"])
    
    {:ok, socket}
  end
  
  @impl true
  def handle_event("toggle_mobile_menu", _params, socket) do
    {:noreply, assign(socket, :mobile_menu_open, !socket.assigns.mobile_menu_open)}
  end
  
  @impl true
  def handle_event("close_mobile_menu", _params, socket) do
    {:noreply, assign(socket, :mobile_menu_open, false)}
  end
  
  @impl true
  def handle_event("validate", %{"signup" => params}, socket) do
    errors = validate_params(params)
    
    socket = 
      socket
      |> assign(:email, Map.get(params, "email", socket.assigns.email))
      |> assign(:company, Map.get(params, "company", socket.assigns.company))
      |> assign(:errors, errors)
    
    {:noreply, socket}
  end
  
  @impl true
  def handle_event("submit", %{"signup" => params}, socket) do
    errors = validate_params(params)
    
    if Enum.empty?(errors) do
      # For now, just show a success message
      socket = 
        socket
        |> put_flash(:success, "Thank you for signing up! We'll be in touch soon.")
        |> assign(:email, "")
        |> assign(:company, "")
      
      {:noreply, socket}
    else
      {:noreply, assign(socket, :errors, errors)}
    end
  end
  
  defp validate_params(params) do
    errors = %{}
    
    email = params["email"] || ""
    
    # Basic email validation
    errors = if email == "" or not String.contains?(email, "@") do
      Map.put(errors, :email, "Please enter a valid email address")
    else
      errors
    end
    
    errors
  end
  
  @impl true
  def render(assigns) do
    ~H"""
    <div class="min-h-screen bg-white">
      <!-- Navigation -->
      <nav class="bg-white shadow">
        <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div class="flex h-16 justify-between">
            <div class="flex">
              <div class="flex flex-shrink-0 items-center">
                <h1 class="text-xl font-bold">RSOLV</h1>
              </div>
            </div>
            <div class="hidden sm:ml-6 sm:flex sm:space-x-8">
              <a href="/blog" class="inline-flex items-center px-1 pt-1 text-sm font-medium text-gray-900">
                Blog
              </a>
              <a href="/signup" class="inline-flex items-center px-1 pt-1 text-sm font-medium text-gray-900">
                Sign Up
              </a>
            </div>
          </div>
        </div>
      </nav>
      
      <!-- Hero Section -->
      <div class="relative isolate px-6 lg:px-8">
        <div class="mx-auto max-w-2xl py-32 sm:py-48 lg:py-56">
          <div class="text-center">
            <h1 class="text-5xl font-semibold tracking-tight text-gray-900 sm:text-7xl">
              Fix Security Issues in Real-Time
            </h1>
            <p class="mt-8 text-lg font-medium text-gray-500 sm:text-xl">
              RSOLV automatically detects and fixes security vulnerabilities in your code. 
              Powered by AI, trusted by developers.
            </p>
            
            <!-- Early Access Form -->
            <div class="mt-10 flex items-center justify-center gap-x-6">
              <form phx-submit="submit" phx-change="validate" class="w-full max-w-md">
                <div class="mt-2">
                  <input
                    type="email"
                    name="signup[email]"
                    value={@email}
                    placeholder="Enter your email"
                    class="block w-full rounded-md border-0 px-4 py-3 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                  />
                  <%= if @errors[:email] do %>
                    <p class="mt-2 text-sm text-red-600"><%= @errors[:email] %></p>
                  <% end %>
                </div>
                
                <div class="mt-4">
                  <input
                    type="text"
                    name="signup[company]"
                    value={@company}
                    placeholder="Company (optional)"
                    class="block w-full rounded-md border-0 px-4 py-3 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                  />
                </div>
                
                <button
                  type="submit"
                  disabled={@submitting}
                  class="mt-4 w-full rounded-md bg-indigo-600 px-8 py-3 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <%= if @submitting, do: "Submitting...", else: "Get Early Access" %>
                </button>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end
end