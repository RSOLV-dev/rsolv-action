#!/usr/bin/env elixir

Mix.Task.run("app.start")

alias RSOLV.Accounts
alias RSOLV.Repo

# Generate a unique API key for the demo
demo_api_key = "rsolv_demo_" <> Base.encode16(:crypto.strong_rand_bytes(12), case: :lower)
email = "dylan@dylanfitzgerald.net"

case Accounts.get_customer_by_email(email) do
  nil ->
    {:ok, customer} = Accounts.create_customer(%{
      email: email,
      name: "Dylan M Fitzgerald", 
      company: "RSOLV Demo",
      api_key: demo_api_key,
      github_username: "dylanfitzgerald",
      subscription_status: "active",
      subscription_tier: "enterprise",  # Give full access for demo
      monthly_limit: 1000,  # Generous limit
      metadata: %{
        "purpose" => "end_to_end_demo",
        "created_for" => "customer_journey_validation"
      }
    })
    
    IO.puts("✅ Created demo customer:")
    IO.puts("   Name: #{customer.name}")
    IO.puts("   Email: #{customer.email}")
    IO.puts("   API Key: #{customer.api_key}")
    IO.puts("   Tier: #{customer.subscription_tier}")
    IO.puts("   GitHub: #{customer.github_username}")
    IO.puts("")
    IO.puts("🔑 GitHub Secret Configuration:")
    IO.puts("   RSOLV_API_KEY=#{customer.api_key}")
  
  customer ->
    IO.puts("ℹ️  Demo customer already exists:")
    IO.puts("   Name: #{customer.name}")
    IO.puts("   Email: #{customer.email}")
    IO.puts("   API Key: #{customer.api_key}")
    IO.puts("   Tier: #{customer.subscription_tier || "none"}")
    IO.puts("")
    IO.puts("🔑 GitHub Secret Configuration:")
    IO.puts("   RSOLV_API_KEY=#{customer.api_key}")
    
    # Update to enterprise tier for demo if needed
    if customer.subscription_tier != "enterprise" do
      {:ok, updated} = Accounts.update_customer(customer, %{
        subscription_tier: "enterprise",
        monthly_limit: 1000
      })
      IO.puts("   Updated to enterprise tier for demo")
    end
end

IO.puts("\n✅ Demo customer ready for end-to-end journey!")