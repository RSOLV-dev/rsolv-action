defmodule Rsolv.Workers.TaggingWorker do
  @moduledoc """
  Oban worker for processing ConvertKit tagging operations.
  Replaces the file-based queue system with reliable job processing.
  """
  use Oban.Worker,
    queue: :email_tagging,
    max_attempts: 3,
    tags: ["convertkit", "tagging"]

  require Logger

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"email" => email, "tag_id" => tag_id, "api_key" => api_key}}) do
    Logger.info("Processing tagging job for #{email} with tag #{tag_id}")

    case process_tag(email, tag_id, api_key) do
      {:ok, subscription_id} ->
        Logger.info(
          "Successfully tagged #{email} with tag #{tag_id} (Subscription ID: #{subscription_id})"
        )

        :ok

      {:error, reason} = error ->
        Logger.error("Failed to tag #{email} with tag #{tag_id}: #{reason}")
        # Return error tuple to trigger retry
        error
    end
  end

  @doc """
  Schedule a tagging job for an email and tag.

  ## Examples

      iex> TaggingWorker.schedule_tagging("user@example.com", "123456")
      {:ok, %Oban.Job{}}

      iex> TaggingWorker.schedule_tagging("user@example.com", "123456", priority: 3)
      {:ok, %Oban.Job{}}
  """
  def schedule_tagging(email, tag_id, opts \\ []) do
    config = Application.get_env(:rsolv, :convertkit, %{})
    api_key = config[:api_key] || raise "ConvertKit API key not configured"

    args = %{
      "email" => email,
      "tag_id" => tag_id,
      "api_key" => api_key
    }

    args
    |> new(opts)
    |> Oban.insert()
  end

  @doc """
  Process a single tagging request.
  Makes an API call to ConvertKit to tag a subscriber.
  Returns {:ok, subscription_id} or {:error, reason}.
  """
  def process_tag(email, tag_id, api_key) do
    # Build the API request
    url = "https://api.convertkit.com/v3/tags/#{tag_id}/subscribe"

    headers = [
      {"Content-Type", "application/json"},
      {"Accept", "application/json"}
    ]

    body =
      JSON.encode!(%{
        api_key: api_key,
        email: email
      })

    # Get the configured HTTP client or default to HTTPoison
    http_client = Application.get_env(:rsolv, :http_client, HTTPoison)

    # Debug log
    Logger.debug("Using HTTP client: #{inspect(http_client)}")

    # Make the API request
    case http_client.post(url, body, headers, recv_timeout: 10_000) do
      {:ok, %HTTPoison.Response{status_code: status_code, body: response_body}}
      when status_code in 200..299 ->
        # Extract subscription ID from response
        subscription_id =
          case JSON.decode(response_body) do
            {:ok, decoded} ->
              get_in(decoded, ["subscription", "id"]) || "unknown"

            _ ->
              "unknown"
          end

        {:ok, to_string(subscription_id)}

      {:ok, %HTTPoison.Response{status_code: status_code, body: response_body}} ->
        {:error, "HTTP Status: #{status_code}, Body: #{response_body}"}

      {:error, %HTTPoison.Error{reason: reason}} ->
        {:error, "HTTP Error: #{inspect(reason)}"}
    end
  end

  @doc """
  Import existing queue entries from CSV file to Oban jobs.
  This is a one-time migration helper.
  """
  def import_from_queue_file(queue_file_path \\ "priv/static/data/tagging_queue/pending_tags.csv") do
    if File.exists?(queue_file_path) do
      queue_content = File.read!(queue_file_path)

      if String.trim(queue_content) != "" do
        entries = String.split(queue_content, "\n", trim: true)

        results =
          Enum.map(entries, fn entry ->
            case String.split(entry, ",", trim: true) do
              [_timestamp, email, tag_id] ->
                schedule_tagging(email, tag_id)

              _ ->
                {:error, "Invalid entry format: #{entry}"}
            end
          end)

        successful = Enum.count(results, &match?({:ok, _}, &1))
        failed = Enum.count(results, &match?({:error, _}, &1))

        Logger.info("Imported #{successful} tagging jobs, #{failed} failed")
        {:ok, %{imported: successful, failed: failed}}
      else
        {:ok, %{imported: 0, failed: 0}}
      end
    else
      {:error, "Queue file not found"}
    end
  end
end
