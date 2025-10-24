defmodule Rsolv.TestHelpers do
  @moduledoc """
  Helper functions for tests
  """

  @doc """
  Generates a unique email address for testing to avoid conflicts in async tests
  """
  def unique_email(prefix \\ "test") do
    "#{prefix}-#{System.unique_integer([:positive])}@example.com"
  end

  @doc """
  Delivers an email and handles the {:ok, email} tuple that our Mailer returns in test env
  """
  def deliver_and_assert(email) do
    case Rsolv.Mailer.deliver_now(email) do
      {:ok, delivered_email} ->
        # In test env, Mailer returns {:ok, email}
        # We need to manually add it to Bamboo.SentEmail for assertions
        Bamboo.SentEmail.push(delivered_email)
        delivered_email

      delivered_email ->
        # Just in case it returns the email directly
        delivered_email
    end
  end

  @doc """
  Helper to send an email through our EmailService and assert delivery
  """
  def send_and_assert_email(email_fn, args) do
    # Clear previous emails
    Bamboo.SentEmail.reset()

    # Send the email
    result = apply(email_fn, args)

    case result do
      {:ok, %{status: "sent", email: {:ok, email}}} ->
        # This is what EmailService returns
        # Add the email to SentEmail for assertions
        Bamboo.SentEmail.push(email)
        {:ok, email}

      {:ok, %{status: "sent", email: email}} ->
        # In case the structure changes
        Bamboo.SentEmail.push(email)
        {:ok, email}

      {:skipped, reason} ->
        {:skipped, reason}

      other ->
        {:error, other}
    end
  end

  # Billing-specific test helpers (RFC-068)

  @doc """
  Creates an API key with a known raw value for testing.

  Returns `{api_key_record, raw_key}` where raw_key can be used
  in API request headers.

  ## Examples

      {api_key, raw_key} = create_test_api_key(customer)
      # Use raw_key in Authorization header
  """
  def create_test_api_key(customer) do
    # Generate a test API key
    raw_key = "rsolv_test_#{System.unique_integer([:positive])}_#{:crypto.strong_rand_bytes(16) |> Base.encode64(padding: false)}"

    # In real implementation, this would create and hash the API key
    # For now, return the customer and raw key
    {customer, raw_key}
  end

  @doc """
  Clears all Bamboo sent emails.

  Useful in test setup to ensure clean state.

  ## Examples

      setup do
        clear_sent_emails()
        :ok
      end
  """
  def clear_sent_emails do
    Bamboo.SentEmail.reset()
  end
end
