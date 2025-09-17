alias Rsolv.{Repo, Customer, APIKey}

# Create or get existing test customer
customer = case Repo.get_by(Customer, email: "test@rsolv.dev") do
  nil ->
    %Customer{
      email: "test@rsolv.dev",
      name: "Test Customer",
      is_staff: false,
      monthly_limit: 1000,
      current_usage: 0,
      subscription_plan: "test",
      subscription_status: "active",
      trial_fixes_used: 0,
      trial_fixes_limit: 10,
      has_payment_method: false
    } |> Repo.insert!()
  existing -> existing
end

# Create new API key
key_value = "rsolv_test_" <> (:crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false))
api_key = %APIKey{
  customer_id: customer.id,
  name: "Test Key for Production Testing",
  key: key_value,
  is_active: true
} |> Repo.insert!()

IO.puts("Created API Key: #{api_key.key}")
IO.puts("Customer ID: #{customer.id}")