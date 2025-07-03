defmodule RsolvWeb.Services.ConvertKit do
  @moduledoc """
  Service for interacting with the ConvertKit API.
  Handles subscriber management, tagging, and tracking.
  """
  require Logger

  @doc """
  Subscribe an email to the early access list.
  Handles tagging, source tracking, and UTM parameter recording.
  Returns :ok on success or {:error, reason} on failure.
  """
  def subscribe_to_early_access(email, options \\ %{}) do
    # Get config values
    config = Application.get_env(:rsolv, :convertkit)
    api_key = config[:api_key]
    form_id = config[:form_id]
    api_base_url = config[:api_base_url]

    # Log details about API key availability
    Logger.info("ConvertKit API key present: #{not is_nil(api_key)}")

    if is_nil(api_key) do
      Logger.warning("ConvertKit API key not configured")
      # Return a mock success in development
      {:ok, %{status: "mocked_success", message: "Development mode"}}
    else
      # Build fields for tracking
      fields = %{
        signup_date: DateTime.utc_now() |> DateTime.to_string(),
        product: "RSOLV",
        early_access: "yes",
        source: Map.get(options, :source, "landing_page")
      }

      # Add UTM parameters if available
      fields = add_utm_params(fields, options)

      # Focus on just adding the subscriber - tags will be handled separately
      try_subscribers_endpoint(email, api_key, form_id, api_base_url, fields)
    end
  end

  # Try the subscribers endpoint first (recommended by ConvertKit)
  defp try_subscribers_endpoint(email, api_key, form_id, api_base_url, fields) do
    url = "#{api_base_url}/subscribers"
    headers = [
      {"Content-Type", "application/json"},
      {"Accept", "application/json"}
    ]

    # Build the request body

    # Now we're only focusing on adding the subscriber, not tagging
    body = Jason.encode!(%{
      api_key: api_key,
      email: email,
      first_name: "RSOLV Subscriber",
      form_id: form_id,
      fields: fields
    })


    case make_api_request(url, body, headers) do
      {:ok, response} ->
        Logger.info("ConvertKit: Successfully added subscriber", metadata: %{email: email})
        {:ok, response}
      {:error, reason} ->
        Logger.warning("ConvertKit: Failed to add subscriber via primary endpoint",
          metadata: %{
            email: email,
            error: inspect(reason)
          }
        )
        # If the subscribers endpoint fails, try the form-specific endpoint as fallback
        Logger.info("ConvertKit: Trying fallback to form-specific endpoint")
        try_form_specific_endpoint(email, api_key, form_id, api_base_url, fields)
    end
  end

  # Fallback to the form-specific endpoint if the subscribers endpoint fails
  defp try_form_specific_endpoint(email, api_key, form_id, api_base_url, fields) do
    # The form-specific endpoint
    url = "#{api_base_url}/forms/#{form_id}/subscribe"
    headers = [
      {"Content-Type", "application/json"},
      {"Accept", "application/json"}
    ]

    # Log that we're trying the fallback endpoint
    Logger.info("ConvertKit: Using form-specific endpoint as fallback for #{email}")

    # Simple request focused on just adding the subscriber
    body = Jason.encode!(%{
      api_key: api_key,
      email: email,
      first_name: "RSOLV Subscriber",
      fields: fields
    })


    case make_api_request(url, body, headers) do
      {:ok, response} ->
        Logger.info("ConvertKit: Successfully added subscriber via fallback endpoint",
          metadata: %{email: email}
        )
        {:ok, response}
      {:error, reason} ->
        Logger.error("ConvertKit: Failed to add subscriber via fallback endpoint",
          metadata: %{
            email: email,
            error: inspect(reason)
          }
        )
        {:error, reason}
    end
  end

  # Add UTM parameters to fields if they exist in options
  defp add_utm_params(fields, options) do
    utm_params = [
      :utm_source,
      :utm_medium,
      :utm_campaign,
      :utm_term,
      :utm_content
    ]

    Enum.reduce(utm_params, fields, fn param, acc ->
      case Map.get(options, param) do
        nil -> acc
        value -> Map.put(acc, param, value)
      end
    end)
  end

  # Helper function to make the API request with error handling
  defp make_api_request(url, body, headers) do

    # Get the configured HTTP client or default to HTTPoison
    http_client = Application.get_env(:rsolv, :http_client, HTTPoison)

    case http_client.post(url, body, headers, [recv_timeout: 10000]) do
      {:ok, %HTTPoison.Response{status_code: status_code} = response} when status_code in 200..299 ->
        Logger.info("ConvertKit API request successful",
          metadata: %{
            status_code: status_code,
            url: url
          }
        )

        # Try to extract subscription ID for analytics
        subscription_id = case Jason.decode(response.body) do
          {:ok, decoded} ->
            get_in(decoded, ["subscription", "id"])
          {:error, error} ->
            Logger.warning("Failed to parse ConvertKit response JSON",
              metadata: %{error: inspect(error)}
            )
            nil
        end

        {:ok, %{
          status_code: status_code,
          body: response.body,
          subscription_id: subscription_id
        }}

      {:ok, %HTTPoison.Response{status_code: status_code} = response} ->
        Logger.warning("ConvertKit API request failed with HTTP error",
          metadata: %{
            status_code: status_code,
            url: url,
            error_body: response.body
          }
        )
        {:error, %{status_code: status_code, body: response.body}}

      {:error, %HTTPoison.Error{reason: reason}} ->
        Logger.error("ConvertKit HTTP request failed",
          metadata: %{
            url: url,
            reason: inspect(reason)
          }
        )
        {:error, %{reason: reason}}
    end
  end

  @doc """
  Add a tag to an existing subscriber. Based on ConvertKit API documentation,
  tagging should be done as a separate operation after subscriber creation.
  Returns :ok on success or {:error, reason} on failure.

  This is a simplified version that uses a more reliable approach to ensure
  tagging happens even if there are issues with the immediate HTTP request.
  It combines immediate tagging with a fallback to append to a tagging queue file.
  """
  def add_tag_to_subscriber(email, tag_id) do
    # Get config values
    config = Application.get_env(:rsolv, :convertkit)
    api_key = config[:api_key]

    # Log the tagging attempt with high visibility
    Logger.info("Attempting to tag subscriber",
      metadata: %{
        email: email,
        tag_id: tag_id
      }
    )

    if is_nil(api_key) do
      Logger.warning("ConvertKit API key not configured for tagging")
      {:ok, %{status: "mocked_success", message: "Development mode"}}
    else
      # Attempt direct tagging first
      api_base_url = config[:api_base_url]
      url = "#{api_base_url}/tags/#{tag_id}/subscribe"
      headers = [
        {"Content-Type", "application/json"},
        {"Accept", "application/json"}
      ]
      body = Jason.encode!(%{
        api_key: api_key,
        email: email
      })

      # Log attempt
      Logger.info("ConvertKit: Attempting to tag #{email} with tag #{tag_id}")

      # Get the configured HTTP client or default to HTTPoison
      http_client = Application.get_env(:rsolv, :http_client, HTTPoison)

      # Try immediate tagging
      case http_client.post(url, body, headers, [recv_timeout: 10000]) do
        {:ok, %HTTPoison.Response{status_code: status_code}} when status_code in 200..299 ->
          Logger.info("ConvertKit: Successfully tagged #{email}")
          {:ok, %{status_code: status_code, message: "Tagged successfully"}}

        _error ->
          # If immediate tagging fails, add to a tagging queue file that can be processed later
          # This ensures we don't lose tagging requests even if the API call fails
          Logger.warning("ConvertKit: Immediate tagging failed, adding to tagging queue")

          _tag_record = %{
            email: email,
            tag_id: tag_id,
            timestamp: DateTime.utc_now() |> DateTime.to_string()
          }


          # Queue the tagging job with Oban
          %{email: email, tag_id: tag_id, api_key: api_key}
          |> Rsolv.Workers.TaggingWorker.new()
          |> Oban.insert()

          # Return success since we've queued the tagging
          {:ok, %{status_code: 200, message: "Tagging queued for later processing"}}
      end
    end
  end

  @doc """
  Unsubscribe an email from all ConvertKit communications.
  This removes the subscriber from the account or marks them as unsubscribed.
  Returns {:ok, response} on success or {:error, reason} on failure.
  """
  def unsubscribe(email) do
    # Get config values
    config = Application.get_env(:rsolv, :convertkit)
    api_key = config[:api_key]
    api_base_url = config[:api_base_url]

    # Log unsubscribe attempt with high visibility
    Logger.info("ConvertKit: Attempting to unsubscribe user",
      metadata: %{
        email: email
      }
    )

    if is_nil(api_key) do
      Logger.warning("ConvertKit API key not configured for unsubscribing")
      # Return a mock success in development
      {:ok, %{status: "mocked_success", message: "Development mode"}}
    else
      # First, get the subscriber ID by email
      subscriber_id = get_subscriber_id(email, api_key, api_base_url)

      case subscriber_id do
        nil ->
          # If we can't find the subscriber, log it and return a success
          # (user wasn't subscribed in the first place)
          Logger.info("ConvertKit: Subscriber not found for unsubscribe",
            metadata: %{email: email}
          )
          {:ok, %{status_code: 200, message: "Subscriber not found"}}

        id ->
          # Got the subscriber ID, now unsubscribe them
          unsubscribe_subscriber(id, api_key, api_base_url, email)
      end
    end
  end

  # Helper to get subscriber ID by email
  defp get_subscriber_id(email, api_key, api_base_url) do
    # Subscribers endpoint for lookup
    url = "#{api_base_url}/subscribers?api_key=#{api_key}&email_address=#{URI.encode_www_form(email)}"
    headers = [
      {"Accept", "application/json"}
    ]

    # Get the configured HTTP client or default to HTTPoison
    http_client = Application.get_env(:rsolv, :http_client, HTTPoison)


    case http_client.get(url, headers, [recv_timeout: 10000]) do
      {:ok, %HTTPoison.Response{status_code: status_code, body: body}} when status_code in 200..299 ->
        # Try to extract subscriber ID from response
        case Jason.decode(body) do
          {:ok, decoded} ->
            # Extract the first subscriber from the list (should be only one)
            subscribers = get_in(decoded, ["subscribers"])
            if subscribers && length(subscribers) > 0 do
              subscriber = List.first(subscribers)
              Map.get(subscriber, "id")
            else
              Logger.info("ConvertKit: No subscribers found for email",
                metadata: %{email: email}
              )
              nil
            end
          {:error, error} ->
            Logger.warning("ConvertKit: Failed to parse subscriber lookup response",
              metadata: %{
                email: email,
                error: inspect(error)
              }
            )
            nil
        end

      _ ->
        # If lookup fails, we can't unsubscribe, so log and return nil
        Logger.warning("ConvertKit: Failed to look up subscriber",
          metadata: %{email: email}
        )
        nil
    end
  end

  # Helper to unsubscribe a subscriber by ID
  defp unsubscribe_subscriber(subscriber_id, api_key, api_base_url, email) do
    # Unsubscribe endpoint
    url = "#{api_base_url}/subscribers/#{subscriber_id}/unsubscribe"
    headers = [
      {"Content-Type", "application/json"},
      {"Accept", "application/json"}
    ]
    body = Jason.encode!(%{
      api_key: api_key
    })

    # Log attempt
    Logger.info("ConvertKit: Attempting to unsubscribe subscriber",
      metadata: %{
        email: email,
        subscriber_id: subscriber_id
      }
    )

    # Get the configured HTTP client or default to HTTPoison
    http_client = Application.get_env(:rsolv, :http_client, HTTPoison)

    case http_client.post(url, body, headers, [recv_timeout: 10000]) do
      {:ok, %HTTPoison.Response{status_code: status_code} = _response} when status_code in 200..299 ->
        Logger.info("ConvertKit: Successfully unsubscribed user",
          metadata: %{
            email: email,
            subscriber_id: subscriber_id
          }
        )
        {:ok, %{status_code: status_code, message: "Unsubscribed successfully"}}

      error ->
        # If unsubscribe fails, log it and then create a fallback record
        Logger.error("ConvertKit: Failed to unsubscribe user",
          metadata: %{
            email: email,
            subscriber_id: subscriber_id,
            error: inspect(error)
          }
        )

        # Record unsubscribe in database even if API call failed
        # This ensures the user won't receive emails even if ConvertKit is down
        Rsolv.EmailManagement.create_unsubscribe(%{
          email: email,
          reason: "ConvertKit API failure - unsubscribe recorded locally"
        })

        {:error, %{message: "Unsubscribe failed, but recorded for retry", email: email}}
    end
  end
end