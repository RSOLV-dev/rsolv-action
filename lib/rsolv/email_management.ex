defmodule Rsolv.EmailManagement do
  @moduledoc """
  The EmailManagement context for managing email unsubscribes and failures.
  """

  import Ecto.Query, warn: false
  alias Rsolv.Repo
  alias Rsolv.EmailManagement.{Unsubscribe, FailedEmail}

  # Unsubscribe functions

  @doc """
  Creates an unsubscribe record.
  """
  def create_unsubscribe(attrs \\ %{}) do
    %Unsubscribe{}
    |> Unsubscribe.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Checks if an email is unsubscribed.
  """
  def is_unsubscribed?(email) do
    normalized_email = String.downcase(email)
    Repo.exists?(from u in Unsubscribe, where: fragment("lower(?)", u.email) == ^normalized_email)
  end

  @doc """
  Returns the list of unsubscribes.
  """
  def list_unsubscribes do
    Repo.all(from u in Unsubscribe, order_by: [desc: u.inserted_at])
  end

  @doc """
  Gets an unsubscribe record by email.
  """
  def get_unsubscribe_by_email(email) do
    Repo.get_by(Unsubscribe, email: email)
  end

  @doc """
  Exports unsubscribes to CSV format.
  """
  def export_unsubscribes_to_csv do
    unsubscribes = list_unsubscribes()

    header = "email,reason,unsubscribed_at\n"

    rows =
      Enum.map(unsubscribes, fn unsub ->
        ~s("#{unsub.email}","#{unsub.reason || ""}","#{unsub.inserted_at}")
      end)

    header <> Enum.join(rows, "\n")
  end

  # Failed email functions

  @doc """
  Creates a failed email record.
  """
  def create_failed_email(attrs \\ %{}) do
    %FailedEmail{}
    |> FailedEmail.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Returns the list of failed emails.
  """
  def list_failed_emails do
    Repo.all(from f in FailedEmail, order_by: [desc: f.inserted_at])
  end

  @doc """
  Returns recent failed emails.
  """
  def list_recent_failed_emails(limit) do
    FailedEmail
    |> order_by([f], desc: f.inserted_at)
    |> limit(^limit)
    |> Repo.all()
  end

  @doc """
  Increments the attempt count for a failed email.
  """
  def increment_failed_email_attempts(%FailedEmail{} = failed_email) do
    failed_email
    |> FailedEmail.changeset(%{attempts: failed_email.attempts + 1})
    |> Repo.update()
  end
end
