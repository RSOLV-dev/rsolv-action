defmodule RsolvWeb.Admin.CustomerLive.Index do
  use RsolvWeb, :live_view
  
  alias Rsolv.Customers
  alias Rsolv.Customers.Customer
  
  @per_page 20
  
  @impl true
  def mount(_params, _session, socket) do
    {:ok, socket}
  end
  
  @impl true
  def handle_params(params, _url, socket) do
    {:noreply, apply_action(socket, socket.assigns.live_action, params)}
  end
  
  defp apply_action(socket, :index, params) do
    page = String.to_integer(params["page"] || "1")
    status = params["status"] || "all"
    sort_by = String.to_atom(params["sort_by"] || "inserted_at")
    sort_order = String.to_atom(params["sort_order"] || "desc")
    
    {customers, total_count} = list_customers(status, sort_by, sort_order, page)
    total_pages = ceil(total_count / @per_page)
    
    socket
    |> assign(:page_title, "Customers")
    |> assign(:customers, customers)
    |> assign(:total_count, total_count)
    |> assign(:total_pages, total_pages)
    |> assign(:current_page, page)
    |> assign(:status_filter, status)
    |> assign(:sort_by, sort_by)
    |> assign(:sort_order, sort_order)
    |> assign(:per_page, @per_page)
  end
  
  @impl true
  def handle_event("sort", %{"field" => field}, socket) do
    field = String.to_atom(field)
    
    # Toggle sort order if clicking the same field
    sort_order = 
      if socket.assigns.sort_by == field do
        if socket.assigns.sort_order == :asc, do: :desc, else: :asc
      else
        :asc
      end
    
    {:noreply,
     push_patch(socket,
       to: ~p"/admin/customers?#{[
         page: 1,
         status: socket.assigns.status_filter,
         sort_by: field,
         sort_order: sort_order
       ]}"
     )}
  end
  
  @impl true
  def handle_event("filter", %{"status" => status}, socket) do
    {:noreply,
     push_patch(socket,
       to: ~p"/admin/customers?#{[
         page: 1,
         status: status,
         sort_by: socket.assigns.sort_by,
         sort_order: socket.assigns.sort_order
       ]}"
     )}
  end
  
  defp list_customers(status, sort_by, sort_order, page) do
    import Ecto.Query
    
    base_query = from(c in Customer)
    
    # Apply status filter
    query = 
      case status do
        "active" -> where(base_query, [c], c.active == true)
        "inactive" -> where(base_query, [c], c.active == false)
        _ -> base_query
      end
    
    # Get total count
    total_count = Rsolv.Repo.aggregate(query, :count)
    
    # Apply sorting and pagination
    offset_value = (page - 1) * @per_page
    
    customers = 
      query
      |> order_by([c], [{^sort_order, field(c, ^sort_by)}])
      |> limit(@per_page)
      |> offset(^offset_value)
      |> Rsolv.Repo.all()
    
    {customers, total_count}
  end
end