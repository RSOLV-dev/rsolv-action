# Create demo customer for end-to-end journey
alias Rsolv.Repo
alias Rsolv.Billing.Customer

# Generate a unique API key for the demo
demo_api_key = "rsolv_demo_" <> Base.encode16(:crypto.strong_rand_bytes(16), case: :lower)

customer_attrs = %{
  name: "Dylan M Fitzgerald", 
  email: "dylan@dylanfitzgerald.net",
  api_key: demo_api_key,
  subscription_plan: "pay_as_you_go",
  trial_fixes_limit: 100,  # Generous for demo
  metadata: %{
    "purpose" => "end_to_end_demo",
    "github_username" => "dylanfitzgerald"
  }
}

changeset = Customer.changeset(%Customer{}, customer_attrs)

case Repo.insert(changeset) do
  {:ok, customer} ->
    IO.puts("✅ Created demo customer: #{customer.name}")
    IO.puts("✅ Email: #{customer.email}")
    IO.puts("✅ API Key: #{customer.api_key}")
    IO.puts("✅ Plan: #{customer.subscription_plan}")
    IO.puts("✅ Trial Fixes: #{customer.trial_fixes_limit}")
    IO.puts("")
    IO.puts("🔑 Save this API key for GitHub secrets:")
    IO.puts("RSOLV_API_KEY=#{customer.api_key}")
    
  {:error, changeset} ->
    IO.puts("❌ Failed to create demo customer")
    IO.inspect(changeset.errors)
end