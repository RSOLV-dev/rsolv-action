defmodule Rsolv.CustomerOnboarding do
  @moduledoc """
  Customer onboarding service. API-ready design with no web dependencies.

  Handles the complete customer onboarding flow: account creation, API key
  generation, and welcome email sequence initiation.

  Can be called from:
  - REST API endpoint
  - LiveView forms (early access, registration)
  - GitHub Marketplace signups (RFC-067)
  - Admin RPC commands
  - Future integrations (webhooks, CLI, OAuth, etc.)
  """

  require Logger

  alias Rsolv.Customers
  alias Rsolv.Customers.Customer
  alias Rsolv.Repo
  alias RsolvWeb.Services.EmailSequence

  @doc """
  Provisions a new customer with all required setup.

  Returns `{:ok, %{customer: customer, api_key: raw_key}}` on success.
  Returns `{:error, reason}` on failure.

  ## Examples

      iex> provision_customer(%{name: "Acme Corp", email: "admin@acme.com"})
      {:ok, %{customer: %Customer{}, api_key: "rsolv_..."}}

      iex> provision_customer(%{email: "invalid"})
      {:error, {:validation_failed, %Ecto.Changeset{}}}
  """
  def provision_customer(attrs) when is_map(attrs) do
    Logger.info(
      "🎯 [CustomerOnboarding] Starting provisioning for #{inspect(attrs["email"] || attrs[:email])}"
    )

    start_time = System.monotonic_time(:millisecond)

    result =
      case validate_email(attrs["email"] || attrs[:email]) do
        :ok ->
          attrs
          |> add_provisioning_defaults()
          |> validate_and_create()

        {:error, reason} ->
          {:error, reason}
      end

    # Emit telemetry event
    emit_telemetry(result, start_time)

    result
  end

  # Validate email against disposable domains
  defp validate_email(nil), do: {:error, {:validation_failed, "email is required"}}

  defp validate_email(email) when is_binary(email) do
    case Burnex.is_burner?(email) do
      true ->
        Logger.warning("🚫 [CustomerOnboarding] Rejected disposable email: #{email}")

        {:error,
         {:validation_failed,
          "email address from temporary/disposable email providers are not allowed"}}

      false ->
        :ok

      {:error, _} ->
        # If burnex fails, allow the email through (fail open)
        Logger.warning(
          "⚠️ [CustomerOnboarding] Burnex check failed for #{email}, allowing through"
        )

        :ok
    end
  end

  # Add default values for auto-provisioned customers
  defp add_provisioning_defaults(attrs) do
    attrs
    |> Map.put_new(:trial_fixes_limit, 5)
    |> Map.put_new(:trial_fixes_used, 0)
    |> Map.put_new(:subscription_type, "trial")
    # State managed by Stripe webhooks
    |> Map.put_new(:subscription_state, nil)
    |> Map.put_new(:has_payment_method, false)
    |> Map.put_new(:auto_provisioned, true)
    |> Map.put_new(:wizard_preference, "auto")
    # Convert string keys to atoms if needed
    |> maybe_atomize_keys()
  end

  # Convert string keys to atoms for consistency
  # Only converts to existing atoms to prevent atom table exhaustion
  defp maybe_atomize_keys(attrs) when is_map(attrs) do
    Map.new(attrs, fn
      {key, value} when is_binary(key) ->
        atom_key =
          try do
            String.to_existing_atom(key)
          rescue
            ArgumentError -> key
          end

        {atom_key, value}

      {key, value} ->
        {key, value}
    end)
  end

  # Validate and create customer with API key in a transaction
  defp validate_and_create(attrs) do
    Ecto.Multi.new()
    |> Ecto.Multi.insert(:customer, build_customer_changeset(attrs))
    |> Ecto.Multi.run(:api_key, fn _repo, %{customer: customer} ->
      create_api_key_for_customer(customer)
    end)
    |> Repo.transaction()
    |> handle_transaction_result()
  end

  # Build changeset for customer creation
  defp build_customer_changeset(attrs) do
    Customer.changeset(%Customer{}, attrs)
  end

  # Create API key for customer
  defp create_api_key_for_customer(customer) do
    Customers.create_api_key(customer, %{
      name: "Default API Key",
      permissions: ["full_access"]
    })
  end

  # Pattern match on successful transaction
  defp handle_transaction_result({:ok, %{customer: customer, api_key: api_key_result}}) do
    Logger.info("✅ [CustomerOnboarding] Successfully provisioned customer #{customer.id}")

    # Extract raw key from the result
    raw_key = api_key_result.raw_key

    # Start onboarding email sequence (Day 0 sent immediately, rest scheduled)
    # IMPORTANT: Email sequence failures are logged but don't block provisioning.
    # Rationale: Customer account and API key are more critical than welcome emails.
    # Failed emails can be retried via admin tools or Oban retry mechanism.
    # NOTE: start_onboarding_sequence/2 always returns {:ok, _result}
    {:ok, _result} =
      EmailSequence.start_onboarding_sequence(customer.email, customer.name)

    Logger.info("✅ [CustomerOnboarding] Email sequence started for customer #{customer.id}")

    # Return customer and raw API key
    {:ok, %{customer: customer, api_key: raw_key}}
  end

  # Pattern match on failed transaction
  defp handle_transaction_result({:error, _failed_operation, changeset, _changes}) do
    Logger.warning("❌ [CustomerOnboarding] Provisioning failed: #{inspect(changeset.errors)}")
    {:error, {:validation_failed, changeset}}
  end

  defp handle_transaction_result({:error, reason}) do
    Logger.error("❌ [CustomerOnboarding] Provisioning failed: #{inspect(reason)}")
    {:error, reason}
  end

  # Emit telemetry events following RFC-060 patterns (RFC-065 Week 3)
  defp emit_telemetry({:ok, %{customer: customer, api_key: _}}, start_time) do
    duration = System.monotonic_time(:millisecond) - start_time

    :telemetry.execute(
      [:rsolv, :customer_onboarding, :complete],
      %{duration: duration, count: 1},
      %{status: "success", customer_id: customer.id, source: "api"}
    )

    Logger.debug("📊 [CustomerOnboarding] Telemetry: success in #{duration}ms")
  end

  defp emit_telemetry({:error, error}, _start_time) do
    reason = format_error_reason(error)

    :telemetry.execute(
      [:rsolv, :customer_onboarding, :failed],
      %{count: 1},
      %{reason: reason, source: "api"}
    )

    Logger.debug("📊 [CustomerOnboarding] Telemetry: failed (#{reason})")
  end

  # Format error reasons for telemetry metadata
  defp format_error_reason({:validation_failed, message}) when is_binary(message), do: message

  defp format_error_reason({:validation_failed, %Ecto.Changeset{errors: errors}}) do
    Enum.map_join(errors, ", ", fn {field, {message, _}} -> "#{field}: #{message}" end)
  end

  defp format_error_reason(other), do: inspect(other)
end
