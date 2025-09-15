defmodule RsolvWeb.Admin.CustomerLive.Index do
  use RsolvWeb, :live_view

  alias Rsolv.Customers
  alias Rsolv.Customers.Customer
  
  @per_page 20
  
  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(:modal_open, false)
     |> assign(:modal_action, nil)
     |> assign(:customer, %Customer{})
     |> assign(:selected_ids, MapSet.new())}
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
    |> assign(:modal_open, false)
    |> assign(:modal_action, nil)
    |> assign(:customer, %Customer{})
    |> assign(:selected_ids, MapSet.new())
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

  @impl true
  def handle_event("new", _params, socket) do
    {:noreply,
     socket
     |> assign(:modal_open, true)
     |> assign(:modal_action, :new)
     |> assign(:customer, %Customer{})}
  end

  @impl true
  def handle_event("edit", %{"id" => id}, socket) do
    customer = Customers.get_customer!(id)
    {:noreply,
     socket
     |> assign(:modal_open, true)
     |> assign(:modal_action, :edit)
     |> assign(:customer, customer)}
  end

  @impl true
  def handle_event("delete", %{"id" => id}, socket) do
    customer = Customers.get_customer!(id)
    {:noreply,
     socket
     |> assign(:modal_open, true)
     |> assign(:modal_action, :delete)
     |> assign(:customer, customer)}
  end

  @impl true
  def handle_event("confirm-delete", %{"id" => id}, socket) do
    customer = Customers.get_customer!(id)
    {:ok, _} = Customers.delete_customer(customer)

    {customers, total_count} = list_customers(
      socket.assigns.status_filter,
      socket.assigns.sort_by,
      socket.assigns.sort_order,
      socket.assigns.current_page
    )

    {:noreply,
     socket
     |> assign(:customers, customers)
     |> assign(:total_count, total_count)
     |> assign(:modal_open, false)
     |> assign(:modal_action, nil)
     |> put_flash(:info, "Customer deleted successfully")}
  end

  @impl true
  def handle_event("cancel", _params, socket) do
    {:noreply,
     socket
     |> assign(:modal_open, false)
     |> assign(:modal_action, nil)}
  end

  @impl true
  def handle_event("save", %{"customer" => customer_params}, socket) do
    save_customer(socket, socket.assigns.modal_action, customer_params)
  end

  @impl true
  def handle_event("toggle-select", %{"id" => id}, socket) do
    id = String.to_integer(id)
    selected_ids = socket.assigns.selected_ids

    new_selected_ids =
      if MapSet.member?(selected_ids, id) do
        MapSet.delete(selected_ids, id)
      else
        MapSet.put(selected_ids, id)
      end

    {:noreply, assign(socket, :selected_ids, new_selected_ids)}
  end

  @impl true
  def handle_event("toggle-all", _params, socket) do
    current_page_ids = Enum.map(socket.assigns.customers, & &1.id)
    selected_ids = socket.assigns.selected_ids

    new_selected_ids =
      if Enum.all?(current_page_ids, &MapSet.member?(selected_ids, &1)) do
        # All selected, deselect all on current page
        Enum.reduce(current_page_ids, selected_ids, &MapSet.delete(&2, &1))
      else
        # Not all selected, select all on current page
        Enum.reduce(current_page_ids, selected_ids, &MapSet.put(&2, &1))
      end

    {:noreply, assign(socket, :selected_ids, new_selected_ids)}
  end

  @impl true
  def handle_event("bulk-action", %{"bulk-actions" => ""}, socket) do
    # No action selected
    {:noreply, socket}
  end

  @impl true
  def handle_event("bulk-action", %{"bulk-actions" => action}, socket) do
    require Logger
    selected_ids = MapSet.to_list(socket.assigns.selected_ids)
    Logger.info("Bulk action triggered: #{action} for #{length(selected_ids)} customers")

    case action do
      "activate" ->
        Enum.each(selected_ids, fn id ->
          customer = Customers.get_customer!(id)
          Customers.update_customer(customer, %{active: true})
        end)

        {:noreply,
         socket
         |> refresh_customers()
         |> assign(:selected_ids, MapSet.new())
         |> put_flash(:info, "#{length(selected_ids)} customers activated")}

      "deactivate" ->
        Enum.each(selected_ids, fn id ->
          customer = Customers.get_customer!(id)
          Customers.update_customer(customer, %{active: false})
        end)

        {:noreply,
         socket
         |> refresh_customers()
         |> assign(:selected_ids, MapSet.new())
         |> put_flash(:info, "#{length(selected_ids)} customers deactivated")}

      "delete" ->
        # Show confirmation modal
        {:noreply,
         socket
         |> assign(:modal_open, true)
         |> assign(:modal_action, :bulk_delete)
         |> assign(:bulk_delete_count, length(selected_ids))}

      _ ->
        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("confirm-bulk-delete", _params, socket) do
    selected_ids = MapSet.to_list(socket.assigns.selected_ids)

    Enum.each(selected_ids, fn id ->
      customer = Customers.get_customer!(id)
      Customers.delete_customer(customer)
    end)

    {:noreply,
     socket
     |> refresh_customers()
     |> assign(:selected_ids, MapSet.new())
     |> assign(:modal_open, false)
     |> assign(:modal_action, nil)
     |> put_flash(:info, "#{length(selected_ids)} customers deleted")}
  end

  defp save_customer(socket, :edit, customer_params) do
    case Customers.update_customer(socket.assigns.customer, customer_params) do
      {:ok, _customer} ->
        {customers, total_count} = list_customers(
          socket.assigns.status_filter,
          socket.assigns.sort_by,
          socket.assigns.sort_order,
          socket.assigns.current_page
        )

        {:noreply,
         socket
         |> assign(:customers, customers)
         |> assign(:total_count, total_count)
         |> assign(:modal_open, false)
         |> assign(:modal_action, nil)
         |> put_flash(:info, "Customer updated successfully")}

      {:error, %Ecto.Changeset{} = changeset} ->
        {:noreply, assign(socket, :changeset, changeset)}
    end
  end

  defp save_customer(socket, :new, customer_params) do
    case Customers.create_customer(customer_params) do
      {:ok, _customer} ->
        {customers, total_count} = list_customers(
          socket.assigns.status_filter,
          socket.assigns.sort_by,
          socket.assigns.sort_order,
          socket.assigns.current_page
        )

        {:noreply,
         socket
         |> assign(:customers, customers)
         |> assign(:total_count, total_count)
         |> assign(:modal_open, false)
         |> assign(:modal_action, nil)
         |> put_flash(:info, "Customer created successfully")}

      {:error, %Ecto.Changeset{} = changeset} ->
        {:noreply, assign(socket, :changeset, changeset)}
    end
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

  defp refresh_customers(socket) do
    {customers, total_count} = list_customers(
      socket.assigns.status_filter,
      socket.assigns.sort_by,
      socket.assigns.sort_order,
      socket.assigns.current_page
    )

    socket
    |> assign(:customers, customers)
    |> assign(:total_count, total_count)
    |> assign(:total_pages, ceil(total_count / @per_page))
  end
end