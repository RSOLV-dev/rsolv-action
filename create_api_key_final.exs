alias Rsolv.{Repo, Customer, APIKey}

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
    }
    |> Repo.insert!()
  existing ->
    existing
end

key_value = "rsolv_prod_test_2025_validated"

Repo.get_by(APIKey, key: key_value)
|> case do
  nil -> :ok
  existing -> Repo.delete!(existing)
end

api_key =
  %APIKey{
    customer_id: customer.id,
    name: "Production Test Key",
    key: key_value,
    is_active: true
  }
  |> Repo.insert!()

IO.puts("Created API Key: #{api_key.key}")