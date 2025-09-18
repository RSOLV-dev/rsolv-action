# Create a test API key for demo purposes
alias Rsolv.Customers
alias Rsolv.Customers.ApiKey

# Get or create test customer
test_customer = case Customers.get_customer_by_name("RSOLV Demo") do
  nil -> 
    {:ok, customer} = Customers.create_customer(%{
      name: "RSOLV Demo",
      email: "demo@rsolv.dev",
      tier: "enterprise"
    })
    customer
  customer -> customer
end

# Create new API key
key = "rsolv_demo_" <> :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
{:ok, _api_key} = Customers.create_api_key(test_customer, %{
  name: "Demo Workflow Key",
  key: key,
  last_four: String.slice(key, -4..-1),
  tier: "enterprise",
  rate_limit: 1000,
  expires_at: DateTime.utc_now() |> DateTime.add(86400, :second)
})

IO.puts("NEW_API_KEY=#{key}")
