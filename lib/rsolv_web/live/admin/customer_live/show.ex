defmodule RsolvWeb.Admin.CustomerLive.Show do
  use RsolvWeb, :live_view
  
  alias Rsolv.Customers
  
  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(:show_edit_modal, false)
     |> assign(:form, nil)
     |> assign(:new_api_key, nil)}
  end
  
  @impl true
  def handle_params(%{"id" => id}, _, socket) do
    customer = Customers.get_customer!(id)
    api_keys = Customers.list_api_keys(customer)
    usage_percentage = calculate_usage_percentage(customer)

    {:noreply,
     socket
     |> assign(:page_title, customer.name)
     |> assign(:customer, customer)
     |> assign(:api_keys, api_keys)
     |> assign(:usage_percentage, usage_percentage)}
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
        usage_percentage = calculate_usage_percentage(customer)

        {:noreply,
         socket
         |> put_flash(:info, "Customer updated successfully")
         |> assign(:customer, customer)
         |> assign(:api_keys, api_keys)
         |> assign(:usage_percentage, usage_percentage)
         |> assign(:show_edit_modal, false)
         |> assign(:form, nil)}

      {:error, changeset} ->
        {:noreply, assign(socket, :form, to_form(changeset))}
    end
  end

  @impl true
  def handle_event("generate-api-key", _, socket) do
    case Customers.create_api_key(socket.assigns.customer, %{name: "API Key"}) do
      {:ok, api_key} ->
        api_keys = Customers.list_api_keys(socket.assigns.customer)

        {:noreply,
         socket
         |> put_flash(:info, "API key generated successfully. Copy it now - it won't be shown again!")
         |> assign(:api_keys, api_keys)
         |> assign(:new_api_key, api_key.key)}

      {:error, _changeset} ->
        {:noreply, put_flash(socket, :error, "Failed to generate API key")}
    end
  end

  @impl true
  def handle_event("close-api-key-modal", _, socket) do
    {:noreply, assign(socket, :new_api_key, nil)}
  end

  defp calculate_usage_percentage(customer) do
    if customer.monthly_limit > 0 do
      percentage = customer.current_usage / customer.monthly_limit * 100
      if percentage == trunc(percentage) do
        trunc(percentage)
      else
        Float.round(percentage, 1)
      end
    else
      0
    end
  end
end