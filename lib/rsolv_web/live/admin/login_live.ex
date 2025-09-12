defmodule RsolvWeb.Admin.LoginLive do
  use RsolvWeb, :live_view
  require Logger
  
  alias Rsolv.Customers
  
  @impl true
  def mount(_params, _session, socket) do
    Logger.info("[Admin LoginLive] Mount - Rendering login form")
    
    socket = 
      socket
      |> assign(:email, "")
      |> assign(:password, "")
      |> assign(:error_message, nil)
      |> assign(:processing, false)
    
    {:ok, socket}
  end
  
  @impl true
  def handle_event("validate", %{"email" => email, "password" => password}, socket) do
    Logger.debug("[Admin LoginLive] Validate - Email: #{email}")
    
    socket = 
      socket
      |> assign(:email, email)
      |> assign(:password, password)
    
    {:noreply, socket}
  end
  
  @impl true
  def handle_event("submit", %{"email" => email, "password" => password}, socket) do
    Logger.info("[Admin LoginLive] Submit - Login attempt for email: #{email}")
    
    socket = 
      socket
      |> assign(:processing, true)
      |> assign(:error_message, nil)
    
    # Send ourselves a message to handle authentication asynchronously
    send(self(), {:authenticate, email, password})
    
    {:noreply, socket}
  end
  
  @impl true
  def handle_info({:authenticate, email, password}, socket) do
    Logger.info("[Admin LoginLive] Authenticating email: #{email}")
    Logger.debug("[Admin LoginLive] Password length: #{String.length(password)}")
    
    # First check if customer exists
    customer_check = Customers.get_customer_by_email(email)
    Logger.info("[Admin LoginLive] Customer lookup result: #{inspect(customer_check != nil)}")
    if customer_check do
      Logger.info("[Admin LoginLive] Customer found - ID: #{customer_check.id}, has_password: #{customer_check.password_hash != nil}")
    end
    
    case Customers.authenticate_customer_by_email_and_password(email, password) do
      {:ok, customer} ->
        Logger.info("[Admin LoginLive] Authentication successful for #{email}, is_staff: #{customer.is_staff}")
        
        if customer.is_staff do
          Logger.info("[Admin LoginLive] Staff user confirmed, logging in #{email}")
          
          # Generate a session token using the Customers module
          token = Customers.generate_customer_session_token(customer)
          
          # Note: We don't store in CustomerSessions here because the AuthController
          # will handle session establishment via CustomerAuth.log_in_customer
          
          socket = 
            socket
            |> put_flash(:info, "Welcome back!")
            |> redirect(to: ~p"/admin/auth?token=#{token}")
          
          {:noreply, socket}
        else
          Logger.warning("[Admin LoginLive] Non-staff user attempted admin login: #{email}")
          
          socket = 
            socket
            |> assign(:processing, false)
            |> assign(:error_message, "You are not authorized to access the admin area.")
          
          {:noreply, socket}
        end
      
      {:error, :invalid_credentials} ->
        Logger.warning("[Admin LoginLive] Invalid credentials for #{email}")
        Logger.debug("[Admin LoginLive] Auth failed - customer exists: #{customer_check != nil}, has_password: #{customer_check && customer_check.password_hash != nil}")
        
        socket = 
          socket
          |> assign(:processing, false)
          |> assign(:error_message, "Invalid email or password")
        
        {:noreply, socket}
      
      {:error, :too_many_attempts} ->
        Logger.warning("[Admin LoginLive] Too many login attempts for #{email}")
        
        socket = 
          socket
          |> assign(:processing, false)
          |> assign(:error_message, "Too many login attempts. Please try again later.")
        
        {:noreply, socket}
      
      error ->
        Logger.error("[Admin LoginLive] Unexpected authentication error for #{email}: #{inspect(error)}")
        Logger.debug("[Admin LoginLive] Full error details: #{inspect(error, pretty: true)}")
        
        socket = 
          socket
          |> assign(:processing, false)
          |> assign(:error_message, "An error occurred during login")
        
        {:noreply, socket}
    end
  end
  
  @impl true
  def render(assigns) do
    ~H"""
    <div class="bg-canvas pb-24 lg:pb-32">
      <div class="sm:px-8 mt-24 sm:mt-32">
        <div class="mx-auto w-full max-w-7xl lg:px-8">
          <div class="relative px-4 sm:px-8 lg:px-12">
            <div class="mx-auto max-w-sm">
              <h1 class="text-2xl font-bold text-center mb-8 text-gray-900 dark:text-gray-100">Admin Login</h1>
      
      <%= if @error_message do %>
        <div class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 px-4 py-3 rounded mb-4">
          <%= @error_message %>
        </div>
      <% end %>
      
      <form phx-change="validate" phx-submit="submit" class="space-y-4">
        <div>
          <label for="email" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">Email</label>
          <input 
            type="email" 
            name="email" 
            id="email" 
            value={@email}
            required 
            disabled={@processing}
            class="w-full px-3 py-2 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 border border-gray-300 dark:border-gray-600 rounded-md focus:ring-blue-500 focus:border-blue-500 disabled:opacity-50" 
          />
        </div>
        
        <div>
          <label for="password" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">Password</label>
          <input 
            type="password" 
            name="password" 
            id="password" 
            value={@password}
            required
            disabled={@processing}
            class="w-full px-3 py-2 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 border border-gray-300 dark:border-gray-600 rounded-md focus:ring-blue-500 focus:border-blue-500 disabled:opacity-50" 
          />
        </div>
        
        <button 
          type="submit" 
          disabled={@processing}
          class="w-full py-2 px-4 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <%= if @processing do %>
            Signing in...
          <% else %>
            Sign In
          <% end %>
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