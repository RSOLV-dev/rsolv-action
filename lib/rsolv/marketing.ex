defmodule Rsolv.Marketing do
  @moduledoc """
  The Marketing context for managing email subscriptions.
  """

  import Ecto.Query, warn: false
  alias Rsolv.Repo

  alias Rsolv.Marketing.EmailSubscription

  @doc """
  Returns the list of email_subscriptions.

  ## Examples

      iex> list_email_subscriptions()
      [%EmailSubscription{}, ...]

  """
  def list_email_subscriptions do
    Repo.all(EmailSubscription)
  end

  @doc """
  Gets a single email_subscription.

  Raises `Ecto.NoResultsError` if the Email subscription does not exist.

  ## Examples

      iex> get_email_subscription!(123)
      %EmailSubscription{}

      iex> get_email_subscription!(456)
      ** (Ecto.NoResultsError)

  """
  def get_email_subscription!(id), do: Repo.get!(EmailSubscription, id)

  @doc """
  Gets an email subscription by email address.
  """
  def get_email_subscription_by_email(email) when is_binary(email) do
    Repo.get_by(EmailSubscription, email: email)
  end

  @doc """
  Creates or updates an email subscription.

  ## Examples

      iex> subscribe_email(%{email: "user@example.com"})
      {:ok, %EmailSubscription{}}

      iex> subscribe_email(%{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def subscribe_email(attrs \\ %{}) do
    case get_email_subscription_by_email(attrs[:email] || attrs["email"]) do
      nil ->
        %EmailSubscription{}
        |> EmailSubscription.changeset(attrs)
        |> Repo.insert()
      
      subscription ->
        # Reactivate if previously unsubscribed
        if subscription.status != "active" do
          update_email_subscription(subscription, %{status: "active", unsubscribed_at: nil})
        else
          {:ok, subscription}
        end
    end
  end

  @doc """
  Updates a email_subscription.

  ## Examples

      iex> update_email_subscription(email_subscription, %{field: new_value})
      {:ok, %EmailSubscription{}}

      iex> update_email_subscription(email_subscription, %{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def update_email_subscription(%EmailSubscription{} = email_subscription, attrs) do
    email_subscription
    |> EmailSubscription.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Unsubscribes an email.

  ## Examples

      iex> unsubscribe_email("user@example.com")
      {:ok, %EmailSubscription{}}

      iex> unsubscribe_email("notfound@example.com")
      {:error, :not_found}

  """
  def unsubscribe_email(email) when is_binary(email) do
    case get_email_subscription_by_email(email) do
      nil ->
        {:error, :not_found}
      
      subscription ->
        update_email_subscription(subscription, %{
          status: "unsubscribed",
          unsubscribed_at: NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second)
        })
    end
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking email_subscription changes.

  ## Examples

      iex> change_email_subscription(email_subscription)
      %Ecto.Changeset{data: %EmailSubscription{}}

  """
  def change_email_subscription(%EmailSubscription{} = email_subscription, attrs \\ %{}) do
    EmailSubscription.changeset(email_subscription, attrs)
  end
end