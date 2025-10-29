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
    require Logger
    customer = socket.assigns.customer

    Logger.info(
      "🔑 [LiveView] Generate API key request for customer_id: #{customer.id}, customer email: #{customer.email}"
    )

    case Customers.create_api_key(customer, %{name: "API Key"}) do
      {:ok, %{record: api_key, raw_key: raw_key}} ->
        Logger.info("🔑 [LiveView] API key created successfully")
        Logger.info("🔑 [LiveView] Displaying key to user: #{raw_key}")
        Logger.info("🔑 [LiveView] API key database ID: #{api_key.id}")

        # Double-check the key can be retrieved (defensive programming)
        case Customers.get_api_key_by_key(raw_key) do
          nil ->
            Logger.error("🔑 [LiveView] CRITICAL ERROR: Key created but not retrievable!")
            Logger.error("🔑 [LiveView] Key that failed: #{raw_key}")

            {:noreply,
             socket
             |> put_flash(
               :error,
               "API key creation failed - key not found in database. Please contact support."
             )}

          _found ->
            Logger.info("🔑 [LiveView] ✅ Verified key is retrievable")

            api_keys = Customers.list_api_keys(customer)

            Logger.info(
              "🔑 [LiveView] Found #{length(api_keys)} total API keys for customer after creation"
            )

            # Log the IDs of all keys to help debugging
            key_ids = Enum.map(api_keys, & &1.id)
            Logger.info("🔑 [LiveView] API key IDs: #{inspect(key_ids)}")

            {:noreply,
             socket
             |> put_flash(
               :info,
               "API key generated successfully. Copy it now - it won't be shown again!"
             )
             |> assign(:api_keys, api_keys)
             |> assign(:new_api_key, raw_key)}
        end

      {:error, changeset} ->
        Logger.error("🔑 [LiveView] Failed to generate API key: #{inspect(changeset.errors)}")

        {:noreply,
         socket
         |> put_flash(:error, "Failed to generate API key: #{format_changeset_errors(changeset)}")}
    end
  end

  @impl true
  def handle_event("close-api-key-modal", _, socket) do
    {:noreply, assign(socket, :new_api_key, nil)}
  end

  defp format_changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, _opts} -> msg end)
    |> Enum.map(fn {field, errors} -> "#{field}: #{Enum.join(errors, ", ")}" end)
    |> Enum.join("; ")
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
