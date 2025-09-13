defmodule RsolvWeb.Admin.LoginLive do
  use RsolvWeb, :live_view
  require Logger
  
  alias Rsolv.Customers
  
  @impl true
  def mount(params, session, socket) do
    try do
      Logger.info("[Admin LoginLive] ====== MOUNT CALLED ======")
      Logger.info("[Admin LoginLive] Mount - Rendering login form")
      Logger.debug("[Admin LoginLive] Mount params: #{inspect(params)}")
      Logger.debug("[Admin LoginLive] Mount session: #{inspect(Map.keys(session))}")
      Logger.debug("[Admin LoginLive] Socket ID: #{inspect(socket.id)}")
      Logger.debug("[Admin LoginLive] Connected?: #{connected?(socket)}")
      
      socket = 
        socket
        |> assign(:email, "")
        |> assign(:password, "")
        |> assign(:error_message, nil)
        |> assign(:processing, false)
      
      Logger.info("[Admin LoginLive] Mount complete, socket assigns: #{inspect(Map.keys(socket.assigns))}")
      {:ok, socket}
    rescue
      error ->
        Logger.error("[Admin LoginLive] Mount error: #{inspect(error)}")
        Logger.error("[Admin LoginLive] Stack trace: #{inspect(__STACKTRACE__)}")
        {:ok, assign(socket, :error_message, "An error occurred loading the page")}
    end
  end
  
  @impl true
  def handle_event("validate", params, socket) do
    try do
      Logger.info("[Admin LoginLive] Validate event received")
      Logger.debug("[Admin LoginLive] Validate params: #{inspect(params)}")
      Logger.debug("[Admin LoginLive] Validate socket assigns: #{inspect(Map.keys(socket.assigns))}")
      
      email = Map.get(params, "email", "")
      password = Map.get(params, "password", "")
      Logger.debug("[Admin LoginLive] Validate - Email: #{email}, Password length: #{String.length(password)}")
      
      socket = 
        socket
        |> assign(:email, email)
        |> assign(:password, password)
      
      {:noreply, socket}
    rescue
      error ->
        Logger.error("[Admin LoginLive] Validate error: #{inspect(error)}")
        Logger.error("[Admin LoginLive] Stack trace: #{inspect(__STACKTRACE__)}")
        {:noreply, assign(socket, :error_message, "Validation error occurred")}
    end
  end
  
  @impl true
  def handle_event("submit", params, socket) do
    try do
      Logger.info("[Admin LoginLive] Submit event received!")
      Logger.debug("[Admin LoginLive] Submit params: #{inspect(params)}")
      Logger.debug("[Admin LoginLive] Submit socket assigns: #{inspect(Map.keys(socket.assigns))}")
      
      email = Map.get(params, "email", "")
      password = Map.get(params, "password", "")
      Logger.info("[Admin LoginLive] Submit - Login attempt for email: #{email}")
      
      socket = 
        socket
        |> assign(:processing, true)
        |> assign(:error_message, nil)
      
      # Send ourselves a message to handle authentication asynchronously
      send(self(), {:authenticate, email, password})
      
      {:noreply, socket}
    rescue
      error ->
        Logger.error("[Admin LoginLive] Submit error: #{inspect(error)}")
        Logger.error("[Admin LoginLive] Stack trace: #{inspect(__STACKTRACE__)}")
        {:noreply, assign(socket, :error_message, "An error occurred during submission")}
    end
  end
  
  @impl true
  def handle_event(event, params, socket) do
    Logger.warning("[Admin LoginLive] Unhandled event: #{event}")
    Logger.debug("[Admin LoginLive] Event params: #{inspect(params)}")
    {:noreply, socket}
  end
  
  @impl true
  def handle_info({:authenticate, email, password}, socket) do
    Logger.info("[Admin LoginLive] Authenticating email: #{email}")
    Logger.debug("[Admin LoginLive] Password length: #{String.length(password)}")
    
    try do
      # First check if customer exists
      customer_check = Customers.get_customer_by_email(email)
      Logger.info("[Admin LoginLive] Customer lookup result: #{inspect(customer_check != nil)}")
      if customer_check do
        Logger.info("[Admin LoginLive] Customer found - ID: #{customer_check.id}, has_password: #{customer_check.password_hash != nil}")
      end
      
      case Customers.authenticate_customer_by_email_and_password(email, password) do
        {:ok, customer} ->
          Logger.info("[Admin LoginLive] ✓ Authentication successful for #{email}, is_staff: #{customer.is_staff}")
          
          if customer.is_staff do
            Logger.info("[Admin LoginLive] ✓ Staff user confirmed, logging in #{email}")
            
            # Generate and store session token for distributed access
            token = Customers.generate_customer_session_token(customer)
            Rsolv.CustomerSessions.put_session(token, customer.id)
            Logger.info("[Admin LoginLive] Session stored in CustomerSessions for customer #{customer.id}")
            
            # Use push_event to trigger JavaScript-based redirect
            # This avoids the LiveView crash issue with redirect/2
            redirect_url = "/admin/auth?token=#{token}"
            Logger.info("[Admin LoginLive] Triggering JavaScript redirect to: #{redirect_url}")
            
            socket = 
              socket
              |> put_flash(:info, "Welcome back!")
              |> push_event("redirect", %{to: redirect_url})
            
            Logger.info("[Admin LoginLive] JavaScript redirect event pushed")
            
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
          Logger.warning("[Admin LoginLive] ✗ Invalid credentials for #{email}")
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
    rescue
      error ->
        Logger.error("[Admin LoginLive] CRASH in authentication handler!")
        Logger.error("[Admin LoginLive] Error type: #{inspect(error.__struct__)}")
        Logger.error("[Admin LoginLive] Error message: #{inspect(Exception.message(error))}")
        Logger.error("[Admin LoginLive] Stack trace: #{inspect(__STACKTRACE__)}")
        
        # Attempt to recover gracefully
        socket = 
          socket
          |> assign(:processing, false)
          |> assign(:error_message, "An unexpected error occurred. Please try again.")
        
        {:noreply, socket}
    end
  end
  
  @impl true
  def render(assigns) do
    ~H"""
    <div class="bg-canvas pb-24 lg:pb-32" id="admin-login" phx-hook="Redirect">
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