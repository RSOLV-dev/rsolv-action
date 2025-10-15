defmodule Rsolv.Feedback do
  @moduledoc """
  The Feedback context for managing user feedback entries.
  """

  import Ecto.Query, warn: false
  alias Rsolv.Repo
  alias Rsolv.Feedback.Entry

  @doc """
  Creates a feedback entry.
  """
  def create_entry(attrs \\ %{}) do
    %Entry{}
    |> Entry.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Returns the list of feedback entries.
  """
  def list_entries do
    Repo.all(Entry)
  end

  @doc """
  Gets a single feedback entry.
  Raises `Ecto.NoResultsError` if the entry does not exist.
  """
  def get_entry!(id), do: Repo.get!(Entry, id)

  @doc """
  Returns the list of feedback entries for a specific email.
  """
  def list_entries_by_email(email) do
    Entry
    |> where([e], e.email == ^email)
    |> Repo.all()
  end

  @doc """
  Returns the count of all feedback entries.
  """
  def count_entries do
    Repo.aggregate(Entry, :count, :id)
  end

  @doc """
  Returns the most recent feedback entries.
  """
  def list_recent_entries(limit) do
    Entry
    |> order_by([e], desc: e.inserted_at)
    |> limit(^limit)
    |> Repo.all()
  end

  @doc """
  Exports all feedback entries to CSV format.
  """
  def export_to_csv do
    entries = list_entries()

    header = "email,message,rating,tags,inserted_at\n"

    rows =
      Enum.map(entries, fn entry ->
        tags = Enum.join(entry.tags || [], ";")

        ~s("#{entry.email}","#{entry.message || ""}","#{entry.rating || ""}","#{tags}","#{entry.inserted_at}")
      end)

    header <> Enum.join(rows, "\n")
  end
end
