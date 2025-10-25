defmodule Rsolv.CustomerOnboarding.Events do
  @moduledoc """
  Context for managing customer onboarding events.

  Provides functions to log audit trail events during customer provisioning
  and onboarding processes.
  """

  import Ecto.Query, warn: false
  alias Rsolv.CustomerOnboarding.Event
  alias Rsolv.Customers.Customer
  alias Rsolv.Repo

  require Logger

  @type event_type :: String.t()
  @type status :: String.t()
  @type metadata :: map()

  @doc """
  Logs a customer_created event.

  ## Examples

      iex> log_customer_created(customer, %{auto_provisioned: true})
      {:ok, %Event{}}

  """
  @spec log_customer_created(Customer.t(), metadata()) ::
          {:ok, Event.t()} | {:error, Ecto.Changeset.t()}
  def log_customer_created(%Customer{} = customer, metadata \\ %{}) do
    log_event(customer, "customer_created", "success", metadata)
  end

  @doc """
  Logs an api_key_generated event.

  ## Examples

      iex> log_api_key_generated(customer, api_key_id)
      {:ok, %Event{}}

  """
  @spec log_api_key_generated(Customer.t(), String.t(), metadata()) ::
          {:ok, Event.t()} | {:error, Ecto.Changeset.t()}
  def log_api_key_generated(%Customer{} = customer, api_key_id, metadata \\ %{}) do
    metadata = Map.put(metadata, :api_key_id, api_key_id)
    log_event(customer, "api_key_generated", "success", metadata)
  end

  @doc """
  Logs an email_sent event.

  ## Examples

      iex> log_email_sent(customer, "success", %{email_type: "welcome"})
      {:ok, %Event{}}

  """
  @spec log_email_sent(Customer.t(), status(), metadata()) ::
          {:ok, Event.t()} | {:error, Ecto.Changeset.t()}
  def log_email_sent(%Customer{} = customer, status, metadata \\ %{})
      when status in ~w(success failed retrying) do
    log_event(customer, "email_sent", status, metadata)
  end

  @doc """
  Generic function to log an onboarding event.

  ## Examples

      iex> log_event(customer, "customer_created", "success", %{source: "api"})
      {:ok, %Event{}}

  """
  def log_event(%Customer{id: customer_id}, event_type, status, metadata \\ %{}) do
    attrs = %{
      customer_id: customer_id,
      event_type: event_type,
      status: status,
      metadata: metadata
    }

    %Event{}
    |> Event.changeset(attrs)
    |> Repo.insert()
    |> tap(fn
      {:ok, _event} ->
        Logger.info(
          "Customer onboarding event logged: #{event_type} (#{status}) for customer #{customer_id}"
        )

      {:error, changeset} ->
        Logger.error(
          "Failed to log customer onboarding event: #{event_type} for customer #{customer_id}, errors: #{inspect(changeset.errors)}"
        )
    end)
  end

  @doc """
  Gets all onboarding events for a customer.

  ## Examples

      iex> list_events(customer)
      [%Event{}, ...]

  """
  @spec list_events(Customer.t()) :: [Event.t()]
  def list_events(%Customer{id: customer_id}) do
    base_query(customer_id)
    |> Repo.all()
  end

  @doc """
  Gets events by type for a customer.

  ## Examples

      iex> list_events_by_type(customer, "api_key_generated")
      [%Event{}, ...]

  """
  @spec list_events_by_type(Customer.t(), event_type()) :: [Event.t()]
  def list_events_by_type(%Customer{id: customer_id}, event_type) do
    base_query(customer_id)
    |> where([e], e.event_type == ^event_type)
    |> Repo.all()
  end

  # Private helper to build base query with common filters and ordering
  defp base_query(customer_id) do
    Event
    |> where([e], e.customer_id == ^customer_id)
    |> order_by([e], desc: e.inserted_at, desc: e.id)
  end
end
