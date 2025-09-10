defmodule Rsolv.CustomersTest do
  use Rsolv.DataCase

  alias Rsolv.Customers

  describe "authenticate_customer_by_email_and_password/2" do
    setup do
      # Reset rate limiter before each test
      Rsolv.RateLimiter.reset()
      # Create a customer with a password
      {:ok, customer} = Customers.register_customer(%{
        email: "test@example.com",
        password: "ValidP@ssw0rd123!",
        name: "Test Customer"
      })
      
      %{customer: customer}
    end

    test "returns customer with correct email and password", %{customer: customer} do
      assert {:ok, authenticated_customer} = 
        Customers.authenticate_customer_by_email_and_password(
          "test@example.com",
          "ValidP@ssw0rd123!"
        )
      
      assert authenticated_customer.id == customer.id
      assert authenticated_customer.email == "test@example.com"
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
      
      # Make 5 failed attempts
      for _ <- 1..5 do
        assert {:error, :invalid_credentials} = 
          Customers.authenticate_customer_by_email_and_password(
            "test@example.com",
            "WrongPassword"
          )
      end

      # 6th attempt should be rate limited
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
        email: "test@example.com",
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
      
      assert {:error, changeset} = Customers.register_customer(%{
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
end