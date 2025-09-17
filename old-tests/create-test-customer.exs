#!/usr/bin/env elixir

Mix.Task.run("app.start")

alias Rsolv.Accounts
alias Rsolv.Repo

# Create a test customer for API testing
email = "test@example.com"
api_key = "test-api-key-12345"

case Accounts.get_customer_by_email(email) do
  nil ->
    {:ok, customer} = Accounts.create_customer(%{
      email: email,
      name: "Test Customer",
      company: "Test Company",
      api_key: api_key,
      github_username: "test-user",
      subscription_status: "active",
      subscription_tier: "enterprise"
    })
    
    IO.puts("✅ Created test customer:")
    IO.puts("   Email: #{customer.email}")
    IO.puts("   API Key: #{customer.api_key}")
    IO.puts("   Tier: #{customer.subscription_tier}")
  
  customer ->
    IO.puts("ℹ️  Test customer already exists:")
    IO.puts("   Email: #{customer.email}")
    IO.puts("   API Key: #{customer.api_key}")
    IO.puts("   Tier: #{customer.subscription_tier || "none"}")
    
    # Update API key if different
    if customer.api_key != api_key do
      {:ok, updated} = Accounts.update_customer(customer, %{api_key: api_key})
      IO.puts("   Updated API key to: #{updated.api_key}")
    end
end

# Also create a few more test customers with different tiers
test_customers = [
  %{email: "demo@example.com", api_key: "demo-key-12345", subscription_tier: nil},
  %{email: "pro@example.com", api_key: "pro-key-12345", subscription_tier: "professional"},
  %{email: "enterprise@example.com", api_key: "enterprise-key-12345", subscription_tier: "enterprise"}
]

Enum.each(test_customers, fn attrs ->
  case Accounts.get_customer_by_email(attrs.email) do
    nil ->
      {:ok, _} = Accounts.create_customer(Map.merge(attrs, %{
        name: "Test #{attrs.subscription_tier || "Demo"} Customer",
        company: "Test Company",
        github_username: "test-#{attrs.subscription_tier || "demo"}",
        subscription_status: if(attrs.subscription_tier, do: "active", else: nil)
      }))
      IO.puts("\n✅ Created #{attrs.email} with tier: #{attrs.subscription_tier || "none"}")
    _ ->
      :ok
  end
end)

IO.puts("\n✅ Test customers ready for API testing!")