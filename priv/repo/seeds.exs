# Script for populating the database. You can run it as:
#
#     mix run priv/repo/seeds.exs

alias Rsolv.Repo
alias Rsolv.Billing.Customer

# Create test customer for dogfooding
dogfood_customer = %Customer{
  name: "RSOLV Internal",
  email: "team@rsolv.dev",
  api_key: "rsolv_dogfood_key",
  active: true,
  metadata: %{
    "type" => "internal",
    "purpose" => "dogfooding"
  }
}

Repo.insert!(dogfood_customer, on_conflict: :nothing, conflict_target: :api_key)

# Create demo customer
demo_customer = %Customer{
  name: "Demo Customer",
  email: "demo@example.com",
  api_key: "rsolv_demo_key_123",
  active: true,
  metadata: %{
    "type" => "demo"
  }
}

Repo.insert!(demo_customer, on_conflict: :nothing, conflict_target: :api_key)

# Create test customer with full access and no quota limits
test_full_access_customer = %Customer{
  name: "Test Full Access",
  email: "test-full-access@rsolv.dev",
  api_key: "rsolv_test_full_access_no_quota_2025",
  active: true,
  trial_fixes_used: 0,
  trial_fixes_limit: 999999,  # Effectively unlimited
  trial_expired: false,
  subscription_plan: "enterprise",
  metadata: %{
    "type" => "test",
    "purpose" => "integration_testing",
    "access_level" => "full",
    "quota_exempt" => true
  }
}

Repo.insert!(test_full_access_customer, on_conflict: :nothing, conflict_target: :api_key)

IO.puts("Seeds complete!")
IO.puts("Created customers with API keys:")
IO.puts("  - rsolv_dogfood_key (internal use)")
IO.puts("  - rsolv_demo_key_123 (demos)")
IO.puts("  - rsolv_test_full_access_no_quota_2025 (full access testing)")