defmodule Rsolv.EmailOptOutService do
  @moduledoc """
  Service for managing email opt-outs and checking if emails are unsubscribed.
  This service ensures we don't send emails to users who have unsubscribed.

  Now uses database-backed storage through EmailManagement context.
  """
  require Logger
  alias Rsolv.EmailManagement

  @doc """
  Checks if an email address has unsubscribed.
  Returns true if the email has unsubscribed, false otherwise.

  Uses cached versions of unsubscribe lists that refresh every hour to avoid
  database queries on every check.
  """
  def is_unsubscribed?(email) when is_binary(email) do
    email = String.downcase(email)

    # Get the cached data or load from database if not cached or cache expired
    unsubscribed_emails = get_unsubscribed_emails()

    # Check if the email is in the unsubscribed list
    MapSet.member?(unsubscribed_emails, email)
  end

  def is_unsubscribed?(_), do: false

  @doc """
  Records an email address as unsubscribed.
  This is useful when receiving webhook callbacks about unsubscribes from
  external services.

  Returns :ok or {:error, reason}
  """
  def record_unsubscribe(email) when is_binary(email) do
    case EmailManagement.create_unsubscribe(%{
           email: String.downcase(email),
           reason: "User request"
         }) do
      {:ok, _unsubscribe} ->
        # Reset the cache to include this new unsubscribe immediately
        invalidate_cache()
        :ok

      {:error, changeset} ->
        Logger.error("Failed to record unsubscribe",
          email: email,
          error: inspect(changeset.errors)
        )

        {:error, changeset}
    end
  end

  @doc """
  Alias for record_unsubscribe/1 for convenience.
  """
  def unsubscribe(email), do: record_unsubscribe(email)

  @doc """
  No longer needed - database handles persistence.
  Kept for backwards compatibility but does nothing.
  """
  def ensure_files_exist do
    :ok
  end

  # Private functions

  # Get a cached list of unsubscribed emails, or load from database if cache expired
  defp get_unsubscribed_emails do
    case get_cache() do
      nil ->
        # Cache miss or expired, load from database
        emails = load_unsubscribed_emails_from_database()
        # Cache the results
        set_cache(emails)
        emails

      emails ->
        # Cache hit
        emails
    end
  end

  # Load unsubscribed emails from database
  defp load_unsubscribed_emails_from_database do
    EmailManagement.list_unsubscribes()
    |> Enum.map(fn unsubscribe -> String.downcase(unsubscribe.email) end)
    |> MapSet.new()
  end

  # Cache implementation with expiration

  # Get cached unsubscribe list
  defp get_cache do
    case :persistent_term.get({__MODULE__, :unsubscribed_emails}, :not_found) do
      :not_found ->
        nil

      {emails, timestamp} ->
        # Check if cache is expired (1 hour)
        if DateTime.diff(DateTime.utc_now(), timestamp, :second) > 3600 do
          nil
        else
          emails
        end
    end
  end

  # Set cache with current timestamp
  defp set_cache(emails) do
    :persistent_term.put({__MODULE__, :unsubscribed_emails}, {emails, DateTime.utc_now()})
  end

  # Invalidate the cache
  defp invalidate_cache do
    :persistent_term.erase({__MODULE__, :unsubscribed_emails})
  end
end
