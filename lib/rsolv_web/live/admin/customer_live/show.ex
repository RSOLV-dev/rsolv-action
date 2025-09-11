defmodule RsolvWeb.Admin.CustomerLive.Show do
  use RsolvWeb, :live_view
  
  alias Rsolv.Customers
  
  @impl true
  def mount(_params, _session, socket) do
    {:ok, socket}
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
end