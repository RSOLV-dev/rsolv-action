# Script for populating the database. You can run it as:
#
#     mix run priv/repo/seeds.exs
#
# This seeds file creates test customers with the new authentication system (RFC-049)

alias Rsolv.Repo
alias Rsolv.Customers
alias Rsolv.Customers.{Customer, ApiKey, ForgeAccount}

IO.puts("Creating seed customers with authentication...")

# Create admin/staff customer
{:ok, admin} =
  Customers.register_customer(%{
    name: "RSOLV Admin",
    email: "admin@rsolv.dev",
    password: "AdminP@ssw0rd2025!",
    is_staff: true,
    admin_level: "full",
    metadata: %{
      "type" => "internal",
      "purpose" => "administration"
    }
  })

# Create API key for admin
{:ok, admin_result} =
  Customers.create_api_key(admin, %{
    name: "Admin API Key",
    raw_key: "rsolv_admin_key_" <> Base.encode16(:crypto.strong_rand_bytes(16)),
    active: true
  })

admin_raw_key = admin_result.raw_key

IO.puts("  ✓ Admin customer created: admin@rsolv.dev (password: AdminP@ssw0rd2025!)")
IO.puts("    API Key: #{admin_raw_key}")

# Create staff member with limited admin
{:ok, staff} =
  Customers.register_customer(%{
    name: "RSOLV Staff",
    email: "staff@rsolv.dev",
    password: "StaffP@ssw0rd2025!",
    is_staff: true,
    admin_level: "limited",
    metadata: %{
      "type" => "internal",
      "purpose" => "support"
    }
  })

{:ok, staff_result} =
  Customers.create_api_key(staff, %{
    name: "Staff API Key",
    raw_key: "rsolv_staff_key_" <> Base.encode16(:crypto.strong_rand_bytes(16)),
    active: true
  })

staff_raw_key = staff_result.raw_key

IO.puts("  ✓ Staff customer created: staff@rsolv.dev (password: StaffP@ssw0rd2025!)")
IO.puts("    API Key: #{staff_raw_key}")

# Create regular customer for testing
{:ok, test_customer} =
  Customers.register_customer(%{
    name: "Test Customer",
    email: "test@example.com",
    password: "TestP@ssw0rd2025!",
    trial_fixes_limit: 100,
    subscription_plan: "trial",
    metadata: %{
      "type" => "test",
      "purpose" => "integration_testing"
    }
  })

{:ok, test_result} =
  Customers.create_api_key(test_customer, %{
    name: "Test API Key",
    raw_key: "rsolv_test_key_123",
    active: true
  })

test_raw_key = test_result.raw_key

IO.puts("  ✓ Test customer created: test@example.com (password: TestP@ssw0rd2025!)")
IO.puts("    API Key: #{test_raw_key}")

# Create demo customer
{:ok, demo_customer} =
  Customers.register_customer(%{
    name: "Demo Customer",
    email: "demo@example.com",
    password: "DemoP@ssw0rd2025!",
    trial_fixes_limit: 50,
    subscription_plan: "trial",
    metadata: %{
      "type" => "demo",
      "purpose" => "demonstrations"
    }
  })

{:ok, demo_result} =
  Customers.create_api_key(demo_customer, %{
    name: "Demo API Key",
    raw_key: "rsolv_demo_key_456",
    active: true
  })

demo_raw_key = demo_result.raw_key

IO.puts("  ✓ Demo customer created: demo@example.com (password: DemoP@ssw0rd2025!)")
IO.puts("    API Key: #{demo_raw_key}")

# Create enterprise customer with no limits
{:ok, enterprise} =
  Customers.register_customer(%{
    name: "Enterprise Customer",
    email: "enterprise@bigcorp.com",
    password: "EnterpriseP@ssw0rd2025!",
    # Effectively unlimited
    trial_fixes_limit: 999_999,
    subscription_plan: "enterprise",
    has_payment_method: true,
    metadata: %{
      "type" => "production",
      "purpose" => "enterprise_customer",
      "quota_exempt" => true
    }
  })

{:ok, enterprise_result} =
  Customers.create_api_key(enterprise, %{
    name: "Enterprise API Key",
    raw_key: "rsolv_enterprise_key_" <> Base.encode16(:crypto.strong_rand_bytes(16)),
    active: true
  })

enterprise_raw_key = enterprise_result.raw_key

IO.puts(
  "  ✓ Enterprise customer created: enterprise@bigcorp.com (password: EnterpriseP@ssw0rd2025!)"
)

IO.puts("    API Key: #{enterprise_raw_key}")

# Create a customer with expired trial
{:ok, expired} =
  Customers.register_customer(%{
    name: "Expired Trial Customer",
    email: "expired@example.com",
    password: "ExpiredP@ssw0rd2025!",
    trial_fixes_used: 5,
    trial_fixes_limit: 5,
    # Expired yesterday
    trial_expired_at: DateTime.add(DateTime.utc_now(), -86400, :second),
    subscription_plan: "trial",
    metadata: %{
      "type" => "test",
      "purpose" => "expired_trial_testing"
    }
  })

{:ok, expired_result} =
  Customers.create_api_key(expired, %{
    name: "Expired Trial API Key",
    raw_key: "rsolv_expired_key_789",
    active: true
  })

expired_raw_key = expired_result.raw_key

IO.puts(
  "  ✓ Expired trial customer created: expired@example.com (password: ExpiredP@ssw0rd2025!)"
)

IO.puts("    API Key: #{expired_raw_key}")

# Create inactive customer for testing
{:ok, inactive} =
  Customers.register_customer(%{
    name: "Inactive Customer",
    email: "inactive@example.com",
    password: "InactiveP@ssw0rd2025!",
    active: false,
    metadata: %{
      "type" => "test",
      "purpose" => "inactive_testing"
    }
  })

{:ok, inactive_result} =
  Customers.create_api_key(inactive, %{
    name: "Inactive API Key",
    raw_key: "rsolv_inactive_key_000",
    # Also inactive
    active: false
  })

inactive_raw_key = inactive_result.raw_key

IO.puts("  ✓ Inactive customer created: inactive@example.com (password: InactiveP@ssw0rd2025!)")
IO.puts("    API Key (inactive): #{inactive_raw_key}")

# ============================================================================
# FORGE ACCOUNTS - Testing Configuration (RFC-067)
# ============================================================================
# For testing three-phase workflow on RSOLV-dev repositories.
# In production, ForgeAccounts are created via GitHub OAuth verification.
# See: projects/go-to-market-2025-10/RFC-067-FORGEACCOUNT-ANALYSIS.md
# ============================================================================

IO.puts("\nCreating ForgeAccounts for testing...")

# Create ForgeAccount for test customer (RSOLV-dev organization)
case Repo.get_by(ForgeAccount,
       customer_id: test_customer.id,
       forge_type: :github,
       namespace: "RSOLV-dev"
     ) do
  nil ->
    {:ok, _forge_account} =
      %ForgeAccount{}
      |> ForgeAccount.changeset(%{
        customer_id: test_customer.id,
        forge_type: :github,
        namespace: "RSOLV-dev",
        # For testing: mark as verified to bypass authorization checks
        # In production: OAuth flow sets this after GitHub verification
        verified_at: DateTime.utc_now(),
        metadata: %{
          "verified_method" => "test_seeding",
          "account_type" => "organization",
          "note" => "Testing account for RSOLV-dev organization repositories",
          "created_for" => "RFC-067 marketplace testing"
        }
      })
      |> Repo.insert()

    IO.puts("  ✓ Created ForgeAccount for RSOLV-dev (test customer)")

  _existing ->
    IO.puts("  ✓ ForgeAccount for RSOLV-dev (test customer) already exists")
end

# Create ForgeAccount for demo customer (RSOLV-dev organization)
case Repo.get_by(ForgeAccount,
       customer_id: demo_customer.id,
       forge_type: :github,
       namespace: "RSOLV-dev"
     ) do
  nil ->
    {:ok, _forge_account} =
      %ForgeAccount{}
      |> ForgeAccount.changeset(%{
        customer_id: demo_customer.id,
        forge_type: :github,
        namespace: "RSOLV-dev",
        verified_at: DateTime.utc_now(),
        metadata: %{
          "verified_method" => "test_seeding",
          "account_type" => "organization",
          "note" => "Testing account for demos"
        }
      })
      |> Repo.insert()

    IO.puts("  ✓ Created ForgeAccount for RSOLV-dev (demo customer)")

  _existing ->
    IO.puts("  ✓ ForgeAccount for RSOLV-dev (demo customer) already exists")
end

IO.puts("\n✅ Seeds complete!")
IO.puts("\nQuick reference:")
IO.puts("  Admin:      admin@rsolv.dev / AdminP@ssw0rd2025!")
IO.puts("  Staff:      staff@rsolv.dev / StaffP@ssw0rd2025!")
IO.puts("  Test:       test@example.com / TestP@ssw0rd2025!")
IO.puts("  Demo:       demo@example.com / DemoP@ssw0rd2025!")
IO.puts("  Enterprise: enterprise@bigcorp.com / EnterpriseP@ssw0rd2025!")
IO.puts("\nNote: All passwords follow RFC-049 security requirements")
IO.puts("ForgeAccounts: Test and Demo customers can access RSOLV-dev repositories")
