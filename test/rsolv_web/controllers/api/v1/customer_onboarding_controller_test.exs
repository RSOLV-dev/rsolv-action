defmodule RsolvWeb.Api.V1.CustomerOnboardingControllerTest do
  use RsolvWeb.ConnCase, async: false

  alias Rsolv.Customers
  alias Rsolv.Repo

  setup do
    # Clear rate limiter for clean tests
    Rsolv.RateLimiter.reset()

    :ok
  end

  describe "POST /api/v1/customers/onboard" do
    test "creates customer with valid data", %{conn: conn} do
      attrs = %{
        "name" => "Test Customer",
        "email" => "test#{System.unique_integer([:positive])}@example.com"
      }

      conn =
        conn
        |> post("/api/v1/customers/onboard", attrs)

      assert %{
               "customer" => %{
                 "id" => customer_id,
                 "name" => "Test Customer",
                 "email" => email
               },
               "api_key" => api_key
             } = json_response(conn, 201)

      assert customer_id
      assert email == attrs["email"]
      assert String.starts_with?(api_key, "rsolv_")

      # Verify customer was actually created
      customer = Customers.get_customer!(customer_id)
      assert customer.name == "Test Customer"
      assert customer.email == attrs["email"]
      assert customer.auto_provisioned == true
      assert customer.trial_fixes_limit == 5
    end

    test "returns error for missing name", %{conn: conn} do
      attrs = %{
        "email" => "test@example.com"
      }

      conn =
        conn
        |> post("/api/v1/customers/onboard", attrs)

      assert %{"error" => %{"message" => message}} = json_response(conn, 422)
      assert message =~ "name"
    end

    test "returns error for missing email", %{conn: conn} do
      attrs = %{
        "name" => "Test Customer"
      }

      conn =
        conn
        |> post("/api/v1/customers/onboard", attrs)

      assert %{"error" => %{"message" => message}} = json_response(conn, 422)
      assert message =~ "email"
    end

    test "returns error for invalid email format", %{conn: conn} do
      attrs = %{
        "name" => "Test Customer",
        "email" => "invalid-email"
      }

      conn =
        conn
        |> post("/api/v1/customers/onboard", attrs)

      assert %{"error" => %{"message" => message}} = json_response(conn, 422)
      assert message =~ "email"
    end

    test "returns error for duplicate email", %{conn: conn} do
      email = "duplicate#{System.unique_integer([:positive])}@example.com"

      # Create first customer
      {:ok, _customer} =
        Customers.create_customer(%{
          name: "First Customer",
          email: email
        })

      # Try to create second customer with same email
      attrs = %{
        "name" => "Second Customer",
        "email" => email
      }

      conn =
        conn
        |> post("/api/v1/customers/onboard", attrs)

      assert %{"error" => %{"message" => message}} = json_response(conn, 422)
      assert message =~ "email" || message =~ "already"
    end

    test "sets initial credit limits correctly", %{conn: conn} do
      attrs = %{
        "name" => "Test Customer",
        "email" => "test#{System.unique_integer([:positive])}@example.com"
      }

      conn =
        conn
        |> post("/api/v1/customers/onboard", attrs)

      assert %{"customer" => %{"id" => customer_id}} = json_response(conn, 201)

      customer = Customers.get_customer!(customer_id)
      assert customer.trial_fixes_limit == 5
      assert customer.trial_fixes_used == 0
      assert customer.subscription_plan == "trial"
      assert customer.subscription_status == "active"
      assert customer.has_payment_method == false
    end
  end
end
