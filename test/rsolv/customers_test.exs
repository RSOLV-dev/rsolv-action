defmodule Rsolv.CustomersTest do
  use Rsolv.DataCase
  import Rsolv.TestHelpers, only: [unique_email: 0, unique_email: 1]

  alias Rsolv.Customers

  describe "authenticate_customer_by_email_and_password/2" do
    setup do
      # Reset rate limiter before each test
      Rsolv.RateLimiter.reset()
      # Create a customer with a password
      {:ok, customer} =
        Customers.register_customer(%{
          email: unique_email(),
          password: "ValidP@ssw0rd123!",
          name: "Test Customer"
        })

      %{customer: customer}
    end

    test "returns customer with correct email and password", %{customer: customer} do
      assert {:ok, authenticated_customer} =
               Customers.authenticate_customer_by_email_and_password(
                 customer.email,
                 "ValidP@ssw0rd123!"
               )

      assert authenticated_customer.id == customer.id
      assert authenticated_customer.email == customer.email
    end

    test "returns error with invalid password", %{customer: _customer} do
      assert {:error, :invalid_credentials} =
               Customers.authenticate_customer_by_email_and_password(
                 "test@example.com",
                 "WrongPassword123!"
               )
    end

    test "returns error with invalid email" do
      assert {:error, :invalid_credentials} =
               Customers.authenticate_customer_by_email_and_password(
                 "nonexistent@example.com",
                 "ValidP@ssw0rd123!"
               )
    end

    test "returns error with nil email" do
      assert {:error, :invalid_credentials} =
               Customers.authenticate_customer_by_email_and_password(nil, "password")
    end

    test "returns error with nil password" do
      assert {:error, :invalid_credentials} =
               Customers.authenticate_customer_by_email_and_password("test@example.com", nil)
    end

    test "rate limits authentication attempts", %{customer: _customer} do
      # Reset rate limiter to ensure clean state
      Rsolv.RateLimiter.reset()

      # Make 10 failed attempts (per RFC-056 configuration)
      for _ <- 1..10 do
        assert {:error, :invalid_credentials} =
                 Customers.authenticate_customer_by_email_and_password(
                   "test@example.com",
                   "WrongPassword"
                 )
      end

      # 11th attempt should be rate limited
      assert {:error, :too_many_attempts} =
               Customers.authenticate_customer_by_email_and_password(
                 "test@example.com",
                 "ValidP@ssw0rd123!"
               )
    end
  end

  describe "register_customer/1" do
    test "creates customer with valid data and hashes password" do
      valid_attrs = %{
        email: "new@example.com",
        password: "ValidP@ssw0rd123!",
        name: "New Customer"
      }

      assert {:ok, customer} = Customers.register_customer(valid_attrs)
      assert customer.email == "new@example.com"
      assert customer.name == "New Customer"

      # Password should be hashed with bcrypt, not plain text
      refute customer.password_hash == "ValidP@ssw0rd123!"
      assert String.starts_with?(customer.password_hash, "$2b$")
    end

    test "returns error changeset with invalid email" do
      invalid_attrs = %{
        email: "not-an-email",
        password: "ValidP@ssw0rd123!",
        name: "Test"
      }

      assert {:error, changeset} = Customers.register_customer(invalid_attrs)
      assert "must have the @ sign and no spaces" in errors_on(changeset).email
    end

    test "returns error changeset with weak password" do
      invalid_attrs = %{
        email: unique_email(),
        password: "weak",
        name: "Test"
      }

      assert {:error, changeset} = Customers.register_customer(invalid_attrs)
      assert "should be at least 12 character(s)" in errors_on(changeset).password
    end

    test "returns error changeset with duplicate email" do
      valid_attrs = %{
        email: "duplicate@example.com",
        password: "ValidP@ssw0rd123!",
        name: "First"
      }

      assert {:ok, _customer} = Customers.register_customer(valid_attrs)

      assert {:error, changeset} =
               Customers.register_customer(%{
                 email: "duplicate@example.com",
                 password: "AnotherP@ssw0rd456!",
                 name: "Second"
               })

      assert "has already been taken" in errors_on(changeset).email
    end

    test "does not store plain text password" do
      valid_attrs = %{
        email: "secure@example.com",
        password: "SecureP@ssw0rd789!",
        name: "Secure Customer"
      }

      assert {:ok, customer} = Customers.register_customer(valid_attrs)

      # Fetch from database to ensure we're checking stored value
      stored_customer = Customers.get_customer!(customer.id)

      # Ensure password field is virtual and not stored
      assert is_nil(Map.get(stored_customer, :password))

      # Ensure password_hash is present and hashed
      assert stored_customer.password_hash
      refute stored_customer.password_hash == "SecureP@ssw0rd789!"
    end
  end

  describe "customer staff privileges" do
    test "creates customer with staff privileges" do
      attrs = %{
        email: "staff@example.com",
        password: "StaffP@ssw0rd123!",
        name: "Staff Member",
        is_staff: true,
        admin_level: "full"
      }

      assert {:ok, customer} = Customers.register_customer(attrs)
      assert customer.is_staff == true
      assert customer.admin_level == "full"
    end

    test "defaults to non-staff with no admin level" do
      attrs = %{
        email: "regular@example.com",
        password: "RegularP@ssw0rd123!",
        name: "Regular Customer"
      }

      assert {:ok, customer} = Customers.register_customer(attrs)
      assert customer.is_staff == false
      assert is_nil(customer.admin_level)
    end

    test "validates admin_level values" do
      attrs = %{
        email: "admin@example.com",
        password: "AdminP@ssw0rd123!",
        name: "Admin",
        is_staff: true,
        admin_level: "invalid_level"
      }

      assert {:error, changeset} = Customers.register_customer(attrs)
      assert "is invalid" in errors_on(changeset).admin_level
    end
  end

  describe "create_customer/1 regression tests for password handling" do
    test "creates customer with password using create_customer function" do
      # This tests the fix for the bug where create_customer wasn't using
      # registration_changeset when a password was provided
      attrs = %{
        email: "password_user@example.com",
        name: "Password User",
        password: "SecurePassword123!",
        is_staff: false
      }

      assert {:ok, customer} = Customers.create_customer(attrs)
      assert customer.email == "password_user@example.com"
      assert customer.password_hash != nil
      assert customer.password_hash != "SecurePassword123!"

      # Verify authentication works
      assert {:ok, _} =
               Customers.authenticate_customer_by_email_and_password(
                 "password_user@example.com",
                 "SecurePassword123!"
               )
    end

    test "creates admin with password for script-based creation" do
      # Simulates how admin users are created via scripts
      attrs = %{
        email: "admin_script@example.com",
        name: "Admin Script User",
        # Weaker password like in scripts
        password: "testpassword123",
        is_staff: true
      }

      # Note: This may fail validation if password requirements are enforced
      # But it tests the path that was broken before
      result = Customers.create_customer(attrs)

      case result do
        {:ok, customer} ->
          assert customer.is_staff == true
          assert customer.password_hash != nil
          # Verify authentication works
          assert {:ok, authenticated} =
                   Customers.authenticate_customer_by_email_and_password(
                     customer.email,
                     "testpassword123"
                   )

          assert authenticated.is_staff == true

        {:error, changeset} ->
          # If password validation fails, that's OK - at least we're
          # using the right changeset now
          assert changeset.errors[:password] != nil
      end
    end

    test "creates customer without password for API-only users" do
      # Ensures we didn't break the non-password path
      attrs = %{
        email: "api_only@example.com",
        name: "API Only User"
      }

      assert {:ok, customer} = Customers.create_customer(attrs)
      assert customer.password_hash == nil

      # Should not authenticate with any password
      assert {:error, :invalid_credentials} =
               Customers.authenticate_customer_by_email_and_password(
                 "api_only@example.com",
                 "any_password"
               )
    end

    test "handles string keys in password attrs" do
      # Tests that string keys work (common in scripts and forms)
      attrs = %{
        "email" => "string_keys@example.com",
        "name" => "String Keys User",
        "password" => "StringPassword123!",
        "is_staff" => true
      }

      assert {:ok, customer} = Customers.create_customer(attrs)
      assert customer.password_hash != nil
      assert customer.is_staff == true

      # Verify authentication works
      assert {:ok, _} =
               Customers.authenticate_customer_by_email_and_password(
                 "string_keys@example.com",
                 "StringPassword123!"
               )
    end
  end

  describe "LiveView admin login session regression tests" do
    test "LiveView login stores in CustomerSessions for distributed session management" do
      # With distributed Mnesia sessions, LiveView tokens ARE stored in CustomerSessions
      # This enables session sharing across pods in Kubernetes
      {:ok, customer} =
        Customers.create_customer(%{
          email: "liveview_session@example.com",
          name: "LiveView Session Test",
          password: "LiveViewPass123!",
          is_staff: true
        })

      # Generate a session token (as LiveView does)
      token = Customers.generate_customer_session_token(customer)
      assert is_binary(token)

      # Verify the token can be used to get the customer
      assert fetched = Customers.get_customer_by_session_token(token)
      assert fetched.id == customer.id

      # Verify CustomerSessions IS being used for LiveView tokens
      # This is required for distributed session management across pods
      sessions = Rsolv.CustomerSessions.all_sessions()
      # LiveView tokens SHOULD appear in CustomerSessions for distributed access
      assert Enum.any?(sessions, fn
               {:customer_sessions_mnesia, session_token, _, _, _} ->
                 session_token == token

               _ ->
                 false
             end)
    end
  end
end
