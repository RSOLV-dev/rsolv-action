# Create test API key for staging AST validation testing
alias RsolvApi.Repo
alias RsolvApi.Billing.Customer

# Generate a unique API key for testing
test_api_key = "rsolv_staging_ast_" <> Base.encode16(:crypto.strong_rand_bytes(16), case: :lower)

customer_attrs = %{
  name: "AST Validation Test", 
  email: "ast-test@rsolv.dev",
  api_key: test_api_key,
  subscription_plan: "pay_as_you_go",
  trial_fixes_limit: 100,
  metadata: %{
    "purpose" => "ast_validation_staging_test",
    "created_at" => DateTime.to_iso8601(DateTime.utc_now())
  }
}

# Check if test customer already exists
case Repo.get_by(Customer, email: "ast-test@rsolv.dev") do
  nil ->
    changeset = Customer.changeset(%Customer{}, customer_attrs)
    case Repo.insert(changeset) do
      {:ok, customer} ->
        IO.puts("✅ Created test customer: #{customer.name}")
        IO.puts("✅ API Key: #{customer.api_key}")
        IO.puts("")
        IO.puts("Export this for testing:")
        IO.puts("export STAGING_API_KEY=#{customer.api_key}")
        
      {:error, changeset} ->
        IO.puts("❌ Failed to create test customer")
        IO.inspect(changeset.errors)
    end
    
  existing ->
    IO.puts("✅ Using existing test customer: #{existing.name}")
    IO.puts("✅ API Key: #{existing.api_key}")
    IO.puts("")
    IO.puts("Export this for testing:")
    IO.puts("export STAGING_API_KEY=#{existing.api_key}")
end