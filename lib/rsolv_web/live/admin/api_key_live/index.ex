defmodule RsolvWeb.Admin.ApiKeyLive.Index do
  use RsolvWeb, :live_view

  alias Rsolv.Customers

  @impl true
  def mount(_params, _session, socket) do
    api_keys = Customers.list_all_api_keys()

    {:ok,
     socket
     |> assign(:api_keys, api_keys)
     |> assign(:original_api_keys, api_keys)
     |> assign(:search_query, "")
     |> assign(:show_delete_confirm, nil)
     |> assign(:show_edit_modal, false)
     |> assign(:editing_key, nil)
     |> assign(:form, nil)}
  end

  @impl true
  def handle_params(params, _url, socket) do
    {:noreply, apply_action(socket, socket.assigns.live_action, params)}
  end

  defp apply_action(socket, :edit, %{"id" => id}) do
    api_key = Customers.get_api_key!(id)
    changeset = Customers.ApiKey.changeset(api_key, %{})

    socket
    |> assign(:page_title, "Edit API Key")
    |> assign(:editing_key, api_key)
    |> assign(:show_edit_modal, true)
    |> assign(:form, to_form(changeset))
  end

  defp apply_action(socket, :index, _params) do
    socket
    |> assign(:page_title, "API Keys Management")
    |> assign(:editing_key, nil)
    |> assign(:show_edit_modal, false)
  end

  @impl true
  def handle_event("search", %{"search" => search_query}, socket) do
    api_keys =
      if search_query == "" do
        socket.assigns.original_api_keys
      else
        Customers.search_api_keys(search_query)
      end

    {:noreply,
     socket
     |> assign(:search_query, search_query)
     |> assign(:api_keys, api_keys)}
  end

  @impl true
  def handle_event("edit", %{"id" => id}, socket) do
    api_key = Customers.get_api_key!(id)
    changeset = Customers.ApiKey.changeset(api_key, %{})

    {:noreply,
     socket
     |> assign(:editing_key, api_key)
     |> assign(:show_edit_modal, true)
     |> assign(:form, to_form(changeset))}
  end

  @impl true
  def handle_event("close_edit_modal", _, socket) do
    {:noreply,
     socket
     |> assign(:show_edit_modal, false)
     |> assign(:editing_key, nil)
     |> assign(:form, nil)}
  end

  @impl true
  def handle_event("validate_api_key", %{"api_key" => api_key_params}, socket) do
    changeset =
      socket.assigns.editing_key
      |> Customers.ApiKey.changeset(api_key_params)
      |> Map.put(:action, :validate)

    {:noreply, assign(socket, :form, to_form(changeset))}
  end

  @impl true
  def handle_event("save_api_key", %{"api_key" => api_key_params}, socket) do
    case Customers.update_api_key(socket.assigns.editing_key, api_key_params) do
      {:ok, _api_key} ->
        api_keys = Customers.list_all_api_keys()

        {:noreply,
         socket
         |> put_flash(:info, "API key updated successfully")
         |> assign(:api_keys, api_keys)
         |> assign(:original_api_keys, api_keys)
         |> assign(:show_edit_modal, false)
         |> assign(:editing_key, nil)
         |> assign(:form, nil)}

      {:error, changeset} ->
        {:noreply, assign(socket, :form, to_form(changeset))}
    end
  end

  @impl true
  def handle_event("toggle-status", %{"id" => id}, socket) do
    api_key = Customers.get_api_key!(id)
    new_status = !api_key.active

    case Customers.update_api_key(api_key, %{active: new_status}) do
      {:ok, _updated_key} ->
        api_keys = Customers.list_all_api_keys()

        {:noreply,
         socket
         |> put_flash(:info, "API key status updated")
         |> assign(:api_keys, api_keys)
         |> assign(:original_api_keys, api_keys)}

      {:error, _changeset} ->
        {:noreply, put_flash(socket, :error, "Failed to update API key status")}
    end
  end

  @impl true
  def handle_event("delete", %{"id" => id}, socket) do
    {:noreply, assign(socket, :show_delete_confirm, String.to_integer(id))}
  end

  @impl true
  def handle_event("cancel-delete", _, socket) do
    {:noreply, assign(socket, :show_delete_confirm, nil)}
  end

  @impl true
  def handle_event("confirm-delete", %{"id" => id}, socket) do
    api_key = Customers.get_api_key!(id)

    case Customers.delete_api_key(api_key) do
      {:ok, _} ->
        api_keys = Customers.list_all_api_keys()

        {:noreply,
         socket
         |> put_flash(:info, "API key deleted successfully")
         |> assign(:api_keys, api_keys)
         |> assign(:original_api_keys, api_keys)
         |> assign(:show_delete_confirm, nil)}

      {:error, _} ->
        {:noreply,
         socket
         |> put_flash(:error, "Failed to delete API key")
         |> assign(:show_delete_confirm, nil)}
    end
  end
end
