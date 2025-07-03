defmodule Rsolv.Billing do
  @moduledoc """
  The Billing context for managing fix attempts and usage tracking.
  """

  import Ecto.Query, warn: false
  alias Rsolv.Repo

  alias Rsolv.Billing.FixAttempt

  @doc """
  Returns the list of fix_attempts.

  ## Examples

      iex> list_fix_attempts()
      [%FixAttempt{}, ...]

  """
  def list_fix_attempts do
    Repo.all(FixAttempt)
  end

  @doc """
  Gets a single fix_attempt.

  Raises `Ecto.NoResultsError` if the Fix attempt does not exist.

  ## Examples

      iex> get_fix_attempt!(123)
      %FixAttempt{}

      iex> get_fix_attempt!(456)
      ** (Ecto.NoResultsError)

  """
  def get_fix_attempt!(id), do: Repo.get!(FixAttempt, id)

  @doc """
  Creates a fix_attempt.

  ## Examples

      iex> create_fix_attempt(%{field: value})
      {:ok, %FixAttempt{}}

      iex> create_fix_attempt(%{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def create_fix_attempt(attrs \\ %{}) do
    %FixAttempt{}
    |> FixAttempt.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a fix_attempt.

  ## Examples

      iex> update_fix_attempt(fix_attempt, %{field: new_value})
      {:ok, %FixAttempt{}}

      iex> update_fix_attempt(fix_attempt, %{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def update_fix_attempt(%FixAttempt{} = fix_attempt, attrs) do
    fix_attempt
    |> FixAttempt.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a fix_attempt.

  ## Examples

      iex> delete_fix_attempt(fix_attempt)
      {:ok, %FixAttempt{}}

      iex> delete_fix_attempt(fix_attempt)
      {:error, %Ecto.Changeset{}}

  """
  def delete_fix_attempt(%FixAttempt{} = fix_attempt) do
    Repo.delete(fix_attempt)
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking fix_attempt changes.

  ## Examples

      iex> change_fix_attempt(fix_attempt)
      %Ecto.Changeset{data: %FixAttempt{}}

  """
  def change_fix_attempt(%FixAttempt{} = fix_attempt, attrs \\ %{}) do
    FixAttempt.changeset(fix_attempt, attrs)
  end

  @doc """
  Lists fix attempts for a customer.

  ## Examples

      iex> list_fix_attempts_for_customer(customer_id)
      [%FixAttempt{}, ...]

  """
  def list_fix_attempts_for_customer(customer_id) do
    FixAttempt
    |> where([f], f.customer_id == ^customer_id)
    |> order_by([f], desc: f.created_at)
    |> Repo.all()
  end

  @doc """
  Gets fix attempt statistics for a customer.

  ## Examples

      iex> get_customer_stats(customer_id)
      %{total_attempts: 10, successful: 8, failed: 2}

  """
  def get_customer_stats(customer_id) do
    stats = FixAttempt
    |> where([f], f.customer_id == ^customer_id)
    |> group_by([f], f.status)
    |> select([f], {f.status, count(f.id)})
    |> Repo.all()
    |> Enum.into(%{})
    
    %{
      total_attempts: Map.values(stats) |> Enum.sum(),
      successful: Map.get(stats, "merged", 0),
      failed: Map.get(stats, "failed", 0) + Map.get(stats, "error", 0),
      pending: Map.get(stats, "pending", 0) + Map.get(stats, "in_progress", 0)
    }
  end

  @doc """
  Records usage data for tracking purposes.
  This is a placeholder implementation during Phase 3 integration.

  ## Examples

      iex> record_usage(%{customer_id: 1, provider: "anthropic", tokens_used: 100})
      {:ok, %{}}

  """
  def record_usage(usage_attrs) do
    # For now, this is a simple logging implementation
    # In the future this could create usage_records or update metrics
    require Logger
    Logger.info("Usage recorded: #{inspect(usage_attrs)}")
    {:ok, usage_attrs}
  end
end