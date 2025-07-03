defmodule RsolvWeb.Components.FeatureCard do
  use Phoenix.Component
  import RsolvWeb.Components.DarkModeHelpers
  
  attr :title, :string, required: true
  attr :description, :string, required: true
  attr :icon, :string, default: nil
  attr :border_color, :string, default: "border-gray-800"
  attr :class, :string, default: ""
  
  def feature_card(assigns) do
    ~H"""
    <div class={card_classes("p-6 rounded-lg shadow-lg h-full flex flex-col border-t-4 #{@border_color} #{@class}")}>
      <%= if @icon do %>
        <div class="flex items-center mb-4">
          <div class={"w-10 h-10 rounded-full #{@icon[:bg_color]} mr-3 flex items-center justify-center"}>
            <span class="text-white font-bold"><%= @icon[:letter] %></span>
          </div>
          <h4 class="text-xl font-bold"><%= @title %></h4>
        </div>
      <% else %>
        <h4 class="text-xl font-bold mb-4"><%= @title %></h4>
      <% end %>
      
      <p class={text_classes(:muted, "flex-grow")}>
        <%= @description %>
      </p>
      
      <%= render_slot(@inner_block) %>
    </div>
    """
  end
end