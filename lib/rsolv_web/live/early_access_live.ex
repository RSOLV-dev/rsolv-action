defmodule RsolvWeb.EarlyAccessLive do
  use RsolvWeb, :live_view

  @impl true
  def mount(_params, _session, socket) do
    socket = 
      socket
      |> assign(:email, "")
      |> assign(:company, "")
      |> assign(:errors, %{})
      |> assign(:submitting, false)
    
    {:ok, socket}
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
    <div class="min-h-screen bg-gray-50">
      <div class="mx-auto max-w-md px-4 py-16 sm:px-6 sm:py-24 lg:px-8">
        <div class="rounded-lg bg-white px-6 py-8 shadow">
          <h2 class="text-3xl font-bold tracking-tight text-gray-900">Get Early Access</h2>
          <p class="mt-4 text-sm text-gray-600">
            Be among the first to use RSOLV and help shape the future of AI-powered security.
          </p>
          
          <form phx-submit="submit" phx-change="validate" class="mt-6 space-y-4">
            <div>
              <label for="email" class="block text-sm font-medium text-gray-700">
                Email address
              </label>
              <input
                type="email"
                name="signup[email]"
                id="email"
                value={@email}
                class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
                placeholder="you@example.com"
              />
              <%= if @errors[:email] do %>
                <p class="mt-2 text-sm text-red-600"><%= @errors[:email] %></p>
              <% end %>
            </div>
            
            <div>
              <label for="company" class="block text-sm font-medium text-gray-700">
                Company (optional)
              </label>
              <input
                type="text"
                name="signup[company]"
                id="company"
                value={@company}
                class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
              />
            </div>
            
            <button
              type="submit"
              disabled={@submitting}
              class="w-full rounded-md bg-indigo-600 py-2 px-4 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600 disabled:opacity-50"
            >
              <%= if @submitting, do: "Submitting...", else: "Request Early Access" %>
            </button>
          </form>
        </div>
      </div>
    </div>
    """
  end
end