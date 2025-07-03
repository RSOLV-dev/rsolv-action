defmodule RsolvWeb.FeedbackComponent do
  use Phoenix.Component
  import RsolvWeb.Components.DarkModeHelpers
  
  @doc """
  Renders a feedback form.
  
  ## Examples
  
      <.feedback_form type="general" />
  
  """
  def feedback_form(assigns) do
    assigns =
      assigns
      |> assign_new(:type, fn -> "general" end)
      |> assign_new(:title, fn -> "Share Your Feedback" end)
      |> assign_new(:prompt, fn -> "We'd love to hear what you think!" end)
      |> assign_new(:button_text, fn -> "Submit Feedback" end)
      |> assign_new(:show_email, fn -> true end)
      |> assign_new(:expanded, fn -> false end)
      |> assign_new(:categories, fn -> [] end)
    
    ~H"""
    <div class="feedback-form-container mt-8 mb-8">
      <div class={card_classes("feedback-form shadow-md rounded px-8 pt-6 pb-8 mb-4 max-w-lg mx-auto")}>
        <%= if @title && @title != "" do %>
          <h3 class="text-xl font-bold mb-4 text-brand-blue dark:text-brand-green"><%= @title %></h3>
        <% end %>
        
        <p class={text_classes(:default, "mb-6")}><%= @prompt %></p>
        
        <form
          data-feedback-form
          data-feedback-type={@type}
          class="space-y-4"
        >
          <%= if Enum.any?(@categories) do %>
            <div class="mb-4">
              <label for="feedback-category" class={label_classes()}>
                Feedback Category
              </label>
              <div class="relative">
                <select
                  id="feedback-category"
                  name="category"
                  class={input_classes()}
                >
                  <%= for category <- @categories do %>
                    <option value={category.id}><%= category.label %></option>
                  <% end %>
                </select>
                <div class="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-gray-700 dark:text-gray-300">
                  <svg class="h-4 w-4 fill-current" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20">
                    <path d="M7 7l3-3 3 3m0 6l-3 3-3-3" style="fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;" />
                  </svg>
                </div>
              </div>
            </div>
          <% end %>
          
          <div class="mb-4">
            <label for="feedback-content" class={label_classes()}>
              Feedback
            </label>
            <textarea
              id="feedback-content"
              name="content"
              rows="4"
              class={input_classes()}
              placeholder="Share your thoughts, ideas, or suggestions..."
              required
            ></textarea>
          </div>
          
          <%= if @show_email do %>
            <div class="mb-4">
              <label for="feedback-email" class={label_classes()}>
                Email (optional)
              </label>
              <input
                type="email"
                id="feedback-email"
                name="email"
                class={input_classes()}
                placeholder="your@email.com"
              />
              <p class={text_classes(:muted, "text-xs mt-1")}>
                We'll only use your email to follow up on your feedback if needed.
              </p>
            </div>
          <% end %>
          
          <div class="flex items-center justify-end">
            <button
              type="submit"
              class="btn-primary"
            >
              <%= @button_text %>
            </button>
          </div>
        </form>
      </div>
    </div>
    """
  end
  
  @doc """
  Renders a feedback button that toggles a feedback form.
  
  ## Examples
  
      <.feedback_button />
  
  """
  def feedback_button(assigns) do
    assigns =
      assigns
      |> assign_new(:text, fn -> "Share Feedback" end)
      |> assign_new(:target, fn -> "feedback-form-container" end)
      |> assign_new(:type, fn -> "general" end)
      |> assign_new(:position, fn -> "fixed" end)
    
    ~H"""
    <div class={"feedback-button-container #{@position == "fixed" && "fixed bottom-4 right-4 z-50"}"}>
      <button
        class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded-full shadow-lg flex items-center space-x-2 transition-all duration-200 ease-in-out transform hover:scale-105"
        data-feedback-trigger
        data-feedback-target={@target}
      >
        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
          <path fill-rule="evenodd" d="M18 5v8a2 2 0 01-2 2h-5l-5 4v-4H4a2 2 0 01-2-2V5a2 2 0 012-2h12a2 2 0 012 2zM7 8H5v2h2V8zm2 0h2v2H9V8zm6 0h-2v2h2V8z" clip-rule="evenodd" />
        </svg>
        <span><%= @text %></span>
      </button>
    </div>
    """
  end
  
  @doc """
  Renders a feedback panel with both button and form.
  
  ## Examples
  
      <.feedback_panel />
  
  """
  def feedback_panel(assigns) do
    assigns =
      assigns
      |> assign_new(:type, fn -> "general" end)
      |> assign_new(:title, fn -> "Share Your Feedback" end)
      |> assign_new(:button_text, fn -> "Share Feedback" end)
    
    form_id = "feedback-form-#{Enum.random(1000..9999)}"
    
    assigns = assign(assigns, :form_id, form_id)
    
    ~H"""
    <div class="feedback-panel">
      <.feedback_button text={@button_text} target={@form_id} type={@type} />
      
      <div id={@form_id} class="hidden">
        <.feedback_form type={@type} title={@title} />
      </div>
    </div>
    """
  end
end