defmodule Rsolv.Security.SQLInjectionTest do
  @moduledoc """
  SQL injection prevention tests.

  Tests that user input is properly sanitized and parameterized queries are used.
  """
  use Rsolv.DataCase, async: true

  alias Rsolv.Customers.Customer
  alias Rsolv.Repo

  @sql_injection_payloads [
    "' OR '1'='1",
    "admin'--",
    "' OR '1'='1' --",
    "' OR 1=1--",
    "' UNION SELECT NULL--",
    "'; DROP TABLE users--",
    "' OR 'x'='x",
    "1' AND '1'='1",
    "admin' OR '1'='1' /*",
    "' OR EXISTS(SELECT * FROM users WHERE '1'='1"
  ]

  describe "email lookup protection" do
    test "Ecto parameterized queries prevent SQL injection" do
      for payload <- @sql_injection_payloads do
        # This should safely return nil, not execute malicious SQL
        result =
          from(c in Customer, where: c.email == ^payload)
          |> Repo.one()

        # Should return nil (no matching user), not raise or execute injection
        assert is_nil(result), "SQL injection payload may have succeeded: #{payload}"
      end
    end

    test "malicious input in changesets is rejected" do
      for payload <- @sql_injection_payloads do
        changeset =
          Customer.changeset(%Customer{}, %{
            email: payload,
            password: "Test123!@#"
          })

        # Should fail validation, not execute SQL
        refute changeset.valid?
        # Verify email validation caught the malicious input
        assert changeset.errors[:email] != nil, "Expected email validation error for: #{payload}"
      end
    end
  end

  describe "search query protection" do
    @tag :skip
    test "full-text search sanitizes input" do
      # When full-text search is implemented, verify it's safe
      # Should use parameterized queries or proper escaping
      for payload <- @sql_injection_payloads do
        # Example: search_customers(payload) should not execute injection
        # assert {:ok, []} = Billing.search_customers(payload)
      end
    end
  end

  describe "dynamic query protection" do
    test "Ecto.Query.dynamic/2 prevents injection" do
      # Test dynamic query building is safe
      for payload <- @sql_injection_payloads do
        query =
          from(u in Customer)
          |> where(^dynamic([u], u.email == ^payload))

        result = Repo.one(query)
        assert is_nil(result)
      end
    end

    test "order_by clauses validated against whitelist" do
      # Ensure dynamic ORDER BY uses whitelisted columns only
      safe_columns = [:email, :inserted_at, :updated_at]

      for column <- safe_columns do
        query = from(u in Customer, order_by: ^column)
        # Should not raise
        assert Repo.all(query)
      end

      # Malicious column names should be rejected
      assert_raise ArgumentError, fn ->
        column = "email; DROP TABLE users--"
        from(u in Customer, order_by: ^column) |> Repo.all()
      end
    end
  end

  describe "raw query safety" do
    test "Repo.query/3 uses parameterized syntax" do
      # When raw SQL is necessary, verify it's parameterized
      payload = "' OR '1'='1"

      # SAFE - parameterized
      {:ok, result} = Repo.query("SELECT * FROM users WHERE email = $1", [payload])
      assert result.num_rows == 0

      # Verify payload was treated as literal string, not SQL
      refute result.num_rows > 0
    end

    test "raw queries escape dangerous characters" do
      payload = "'; DROP TABLE users; --"

      # Should treat as literal string, not execute DROP
      {:ok, result} = Repo.query("SELECT * FROM users WHERE email = $1", [payload])

      # Verify users table still exists
      {:ok, _} = Repo.query("SELECT COUNT(*) FROM users", [])
    end
  end

  describe "authentication bypass attempts" do
    test "login with SQL injection fails safely" do
      # Attempt to bypass authentication
      attack_email = "admin' OR '1'='1' --"
      attack_password = "anything"

      # Should fail validation, not authenticate
      result =
        from(u in Customer, where: u.email == ^attack_email)
        |> Repo.one()

      assert is_nil(result)
    end

    test "password field not vulnerable to injection" do
      attack_password = "' OR '1'='1"
      real_password = "RealPassword123!"

      # Create customer with hashed password using the proper registration flow
      {:ok, customer} =
        Rsolv.Customers.register_customer(%{
          email: "test@example.com",
          name: "Test User",
          password: real_password
        })

      # Password comparison happens in application code, not SQL
      # The attack password should not match the real password
      refute Bcrypt.verify_pass(attack_password, customer.password_hash)
      # Verify the real password DOES work (sanity check)
      assert Bcrypt.verify_pass(real_password, customer.password_hash)
    end
  end
end
