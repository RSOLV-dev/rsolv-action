defmodule RsolvWeb.ContactLive do
  use RsolvWeb, :live_view
  require Logger
  alias RsolvWeb.Services.Analytics
  alias RsolvWeb.Validators.EmailValidator
  alias Rsolv.Emails
  alias Rsolv.Mailer

  @impl true
  def mount(_params, _session, socket) do
    # Track page view
    Analytics.track_page_view("/contact", nil, extract_tracking_data(socket))
    
    {:ok, 
     socket
     |> assign(form: to_form(%{}))
     |> assign(submitted: false)
     |> assign(error: nil)}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="min-h-screen bg-gray-50 dark:bg-dark-950">
      <!-- Header -->
      <header class="fixed top-0 left-0 right-0 z-50 transition-all duration-300 bg-white/80 dark:bg-dark-900/80 backdrop-blur-sm">
        <div class="container mx-auto px-4 sm:px-6 lg:px-8">
          <div class="flex items-center justify-between py-4 text-sm">
            <div class="flex items-center gap-4">
              <a href="/" class="flex items-center">
                <img src="/images/rsolv_logo_transparent.png" width="100" alt="RSOLV - Automatic Security Detection">
              </a>
            </div>
            <nav class="hidden md:flex items-center gap-8">
              <a href="/#features" class="font-medium text-gray-700 dark:text-white/90 hover:text-gray-900 dark:hover:text-white transition-colors">Features</a>
              <a href="/#pricing" class="font-medium text-gray-700 dark:text-white/90 hover:text-gray-900 dark:hover:text-white transition-colors">Pricing</a>
              <a href="/#early-access" class="btn-primary">Get Started</a>
            </nav>
          </div>
        </div>
      </header>

      <!-- Contact Section -->
      <section class="pt-32 pb-20">
        <div class="container mx-auto px-4">
          <div class="max-w-4xl mx-auto">
            <h1 class="text-4xl md:text-5xl font-bold mb-6 text-gray-900 dark:text-white">Contact Sales</h1>
            
            <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
              <!-- Contact Form -->
              <div class="bg-white dark:bg-dark-800 rounded-lg shadow-lg p-8">
                <h2 class="text-2xl font-semibold mb-6 text-gray-900 dark:text-white">Send us a message</h2>
                
                <%= if @submitted do %>
                  <div class="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-6 text-center">
                    <span class="hero-solid-check-circle w-12 h-12 text-green-500 mx-auto mb-3 block"></span>
                    <h3 class="text-lg font-semibold text-green-800 dark:text-green-200 mb-2">Thank you for contacting us!</h3>
                    <p class="text-green-700 dark:text-green-300">We'll get back to you within 24 business hours.</p>
                  </div>
                <% else %>
                  <.form for={@form} phx-submit="submit" class="space-y-4">
                    <div>
                      <label for="name" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Name <span class="text-red-500">*</span>
                      </label>
                      <input 
                        type="text" 
                        id="name" 
                        name="name" 
                        required
                        class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:ring-brand-blue focus:border-brand-blue dark:bg-dark-700 dark:text-white"
                        placeholder="John Doe"
                      />
                    </div>
                    
                    <div>
                      <label for="email" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Email <span class="text-red-500">*</span>
                      </label>
                      <input 
                        type="email" 
                        id="email" 
                        name="email" 
                        required
                        class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:ring-brand-blue focus:border-brand-blue dark:bg-dark-700 dark:text-white"
                        placeholder="john@company.com"
                      />
                    </div>
                    
                    <div>
                      <label for="company" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Company
                      </label>
                      <input 
                        type="text" 
                        id="company" 
                        name="company"
                        class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:ring-brand-blue focus:border-brand-blue dark:bg-dark-700 dark:text-white"
                        placeholder="Acme Inc."
                      />
                    </div>
                    
                    <div>
                      <label for="message" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Message <span class="text-red-500">*</span>
                      </label>
                      <textarea 
                        id="message" 
                        name="message" 
                        rows="4"
                        required
                        class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:ring-brand-blue focus:border-brand-blue dark:bg-dark-700 dark:text-white"
                        placeholder="Tell us about your security needs..."
                      ></textarea>
                    </div>
                    
                    <div>
                      <label for="team_size" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Team Size
                      </label>
                      <select 
                        id="team_size" 
                        name="team_size"
                        class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:ring-brand-blue focus:border-brand-blue dark:bg-dark-700 dark:text-white"
                      >
                        <option value="">Select team size</option>
                        <option value="1-10">1-10 developers</option>
                        <option value="11-50">11-50 developers</option>
                        <option value="51-200">51-200 developers</option>
                        <option value="201+">201+ developers</option>
                      </select>
                    </div>
                    
                    <%= if @error do %>
                      <div class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded p-3">
                        <p class="text-sm text-red-700 dark:text-red-300"><%= @error %></p>
                      </div>
                    <% end %>
                    
                    <button type="submit" class="w-full btn-primary">
                      Send Message
                    </button>
                  </.form>
                <% end %>
              </div>
              
              <!-- Contact Info -->
              <div class="space-y-8">
                <div class="bg-white dark:bg-dark-800 rounded-lg shadow-lg p-8">
                  <h3 class="text-xl font-semibold mb-4 text-gray-900 dark:text-white">Get in Touch</h3>
                  <ul class="space-y-3">
                    <li class="flex items-start">
                      <span class="hero-solid-envelope w-5 h-5 text-brand-green mr-3 mt-1"></span>
                      <div>
                        <p class="font-medium text-gray-900 dark:text-white">Email</p>
                        <a href="mailto:sales@rsolv.dev" class="text-brand-blue hover:underline">sales@rsolv.dev</a>
                      </div>
                    </li>
                    <li class="flex items-start">
                      <span class="hero-solid-chat-bubble-left-right w-5 h-5 text-brand-green mr-3 mt-1"></span>
                      <div>
                        <p class="font-medium text-gray-900 dark:text-white">Response Time</p>
                        <p class="text-gray-600 dark:text-gray-400">Within 24 business hours</p>
                      </div>
                    </li>
                  </ul>
                </div>
                
                <div class="bg-white dark:bg-dark-800 rounded-lg shadow-lg p-8">
                  <h3 class="text-xl font-semibold mb-4 text-gray-900 dark:text-white">Enterprise Features</h3>
                  <ul class="space-y-2">
                    <li class="flex items-start">
                      <span class="hero-solid-check-circle w-5 h-5 text-brand-green mr-2 mt-0.5"></span>
                      <span class="text-gray-600 dark:text-gray-300">Volume pricing</span>
                    </li>
                    <li class="flex items-start">
                      <span class="hero-solid-check-circle w-5 h-5 text-brand-green mr-2 mt-0.5"></span>
                      <span class="text-gray-600 dark:text-gray-300">Custom security patterns</span>
                    </li>
                    <li class="flex items-start">
                      <span class="hero-solid-check-circle w-5 h-5 text-brand-green mr-2 mt-0.5"></span>
                      <span class="text-gray-600 dark:text-gray-300">SLA guarantees</span>
                    </li>
                    <li class="flex items-start">
                      <span class="hero-solid-check-circle w-5 h-5 text-brand-green mr-2 mt-0.5"></span>
                      <span class="text-gray-600 dark:text-gray-300">Dedicated support</span>
                    </li>
                    <li class="flex items-start">
                      <span class="hero-solid-check-circle w-5 h-5 text-brand-green mr-2 mt-0.5"></span>
                      <span class="text-gray-600 dark:text-gray-300">On-premise deployment options</span>
                    </li>
                  </ul>
                </div>
                
                <div class="bg-brand-light dark:bg-dark-800 rounded-lg p-6 text-center">
                  <p class="text-lg mb-4 text-gray-700 dark:text-gray-300">
                    Ready to start with our standard plans?
                  </p>
                  <a href="/#early-access" class="btn-primary">Start Risk-Free - 10 Free Fixes</a>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
    """
  end

  @impl true
  def handle_event("submit", params, socket) do
    # Validate email
    case EmailValidator.validate_with_feedback(params["email"]) do
      {:ok, _} ->
        # Send email notification
        contact_data = %{
          name: params["name"],
          email: params["email"],
          company: params["company"] || "Not provided",
          message: params["message"],
          team_size: params["team_size"] || "Not specified",
          timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
          source: "contact_form"
        }
        
        # Track form submission
        Analytics.track_form_submission("contact", "submit", Map.put(extract_tracking_data(socket), :email, params["email"]))
        
        # Send admin notification
        try do
          email = Emails.contact_form_notification(contact_data)
          Mailer.deliver_now(email)
          
          Logger.info("Contact form submission sent", metadata: contact_data)
          
          # Track success
          Analytics.track_form_submission("contact", "success", contact_data)
          
          {:noreply, assign(socket, submitted: true, error: nil)}
        rescue
          e ->
            Logger.error("Failed to send contact form email", error: inspect(e))
            {:noreply, assign(socket, error: "Failed to send message. Please try again or email us directly at sales@rsolv.dev")}
        end
        
      {:error, error_message} ->
        # Track error
        Analytics.track_form_submission("contact", "error", %{
          error_type: "validation",
          error_details: error_message,
          email_input: params["email"]
        })
        
        {:noreply, assign(socket, error: error_message)}
    end
  end
  
  # Extract tracking data helper
  defp extract_tracking_data(_socket) do
    %{
      timestamp: DateTime.utc_now() |> DateTime.to_string(),
      page_path: "/contact",
      form_type: "contact_sales"
    }
  end
end