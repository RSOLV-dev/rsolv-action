defmodule RsolvWeb.Admin.CustomerLive.Show do
  use RsolvWeb, :live_view
  
  alias Rsolv.Customers
  
  @impl true
  def mount(_params, session, socket) do
    # Check for staff authentication
    case session do
      %{"customer_token" => token} when is_binary(token) ->
        customer = Rsolv.Customers.get_customer_by_session_token(token)
        
        cond do
          is_nil(customer) ->
            {:ok,
             socket
             |> Phoenix.LiveView.put_flash(:error, "You must be logged in to access this page.")
             |> Phoenix.LiveView.redirect(to: "/admin/login")}
          
          not customer.is_staff ->
            {:ok,
             socket
             |> Phoenix.LiveView.put_flash(:error, "You are not authorized to access this page.")
             |> Phoenix.LiveView.redirect(to: "/")}
          
          true ->
            {:ok, 
             socket
             |> assign(:current_customer, customer)
             |> assign(:show_edit_modal, false)
             |> assign(:form, nil)}
        end
      
      _ ->
        {:ok,
         socket
         |> Phoenix.LiveView.put_flash(:error, "You must be logged in to access this page.")
         |> Phoenix.LiveView.redirect(to: "/admin/login")}
    end
  end
  
  @impl true
  def handle_params(%{"id" => id}, _, socket) do
    customer = Customers.get_customer!(id)
    api_keys = Customers.list_api_keys(customer)
    
    {:noreply,
     socket
     |> assign(:page_title, customer.name)
     |> assign(:customer, customer)
     |> assign(:api_keys, api_keys)}
  end
  
  @impl true
  def handle_event("open_edit_modal", _, socket) do
    changeset = Customers.change_customer(socket.assigns.customer)
    
    {:noreply,
     socket
     |> assign(:show_edit_modal, true)
     |> assign(:form, to_form(changeset))}
  end
  
  @impl true
  def handle_event("close_edit_modal", _, socket) do
    {:noreply,
     socket
     |> assign(:show_edit_modal, false)
     |> assign(:form, nil)}
  end
  
  @impl true
  def handle_event("validate_customer", %{"customer" => customer_params}, socket) do
    changeset =
      socket.assigns.customer
      |> Customers.change_customer(customer_params)
      |> Map.put(:action, :validate)
    
    {:noreply, assign(socket, :form, to_form(changeset))}
  end
  
  @impl true
  def handle_event("save_customer", %{"customer" => customer_params}, socket) do
    case Customers.update_customer(socket.assigns.customer, customer_params) do
      {:ok, customer} ->
        api_keys = Customers.list_api_keys(customer)
        
        {:noreply,
         socket
         |> put_flash(:info, "Customer updated successfully")
         |> assign(:customer, customer)
         |> assign(:api_keys, api_keys)
         |> assign(:show_edit_modal, false)
         |> assign(:form, nil)}
      
      {:error, changeset} ->
        {:noreply, assign(socket, :form, to_form(changeset))}
    end
  end
end