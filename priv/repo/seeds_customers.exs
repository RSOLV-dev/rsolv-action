# Script for creating test customers
alias RSOLV.Accounts

# Create a test enterprise customer with all access
Accounts.create_customer(%{
  name: "Test Enterprise Customer",
  email: "test@rsolv.dev",
  api_key: "rsolv_test_enterprise_key_123456",
  tier: "enterprise",
  ai_enabled: true,
  is_active: true,
  metadata: %{
    "test_account" => true,
    "created_for" => "RFC-008 Pattern API testing"
  }
})

# Create a teams customer
Accounts.create_customer(%{
  name: "Test Teams Customer", 
  email: "teams@rsolv.dev",
  api_key: "rsolv_test_teams_key_789012",
  tier: "teams",
  ai_enabled: false,
  is_active: true
})

IO.puts("✅ Created test customers with API keys")