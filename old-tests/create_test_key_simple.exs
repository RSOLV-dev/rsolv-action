alias Rsolv.{Repo, Customer, APIKey}

# Get or create test customer
customer =
  case Repo.get_by(Customer, email: "test@rsolv.dev") do
    nil ->
      %Customer{
        email: "test@rsolv.dev",
        name: "Production Test Customer",
        is_staff: false,
        monthly_limit: 1000,
        current_usage: 0,
        subscription_plan: "test",
        subscription_status: "active",
        trial_fixes_used: 0,
        trial_fixes_limit: 10,
        has_payment_method: false
      }
      |> Repo.insert!()
    existing ->
      existing
  end

# Create API key with known value for testing
key_value = "rsolv_prod_test_2025_api_key_for_validation"

# Delete existing key if present
Repo.get_by(APIKey, key: key_value) |> case do
  nil -> :ok
  existing -> Repo.delete!(existing)
end

# Create new key
api_key =
  %APIKey{
    customer_id: customer.id,
    name: "Production Test Key",
    key: key_value,
    is_active: true
  }
  |> Repo.insert!()

IO.puts("SUCCESS: Created API Key: #{api_key.key}")
IO.puts("Customer Email: #{customer.email}")
IO.puts("Customer ID: #{customer.id}")