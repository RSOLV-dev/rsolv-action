# Direct test of Slack webhook
# Run with: mix run test_direct_slack.exs

webhook_url = System.get_env("SLACK_WEBHOOK_URL")
IO.puts("Webhook URL configured: #{webhook_url != nil}")

if webhook_url do
  IO.puts("Webhook URL length: #{String.length(webhook_url)}")
  IO.puts("Webhook URL starts with: #{String.slice(webhook_url, 0..30)}...")

  # Test direct HTTP request
  body =
    JSON.encode!(%{
      text: "Test message from RSOLV API - Direct test",
      blocks: [
        %{
          type: "section",
          text: %{
            type: "mrkdwn",
            text: "🔐 *Direct Slack Test* - If you see this, the webhook is working!"
          }
        }
      ]
    })

  case HTTPoison.post(webhook_url, body, [{"Content-Type", "application/json"}]) do
    {:ok, %{status_code: 200}} ->
      IO.puts("✅ Success! Message sent to Slack")

    {:ok, %{status_code: code, body: body}} ->
      IO.puts("❌ Slack returned error #{code}: #{body}")

    {:error, error} ->
      IO.puts("❌ HTTP error: #{inspect(error)}")
  end
else
  IO.puts("❌ SLACK_WEBHOOK_URL environment variable not set!")
end
