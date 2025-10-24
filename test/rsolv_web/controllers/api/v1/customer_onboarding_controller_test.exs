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
    test "rejects disposable email domains", %{conn: conn} do
      disposable_emails = [
        "test@mailinator.com",
        "test@guerrillamail.com",
        "test@10minutemail.com",
        "test@temp-mail.org"
      ]

      for email <- disposable_emails do
        attrs = %{
          "name" => "Test Customer",
          "email" => email
        }

        conn =
          build_conn()
          |> post("/api/v1/customers/onboard", attrs)

        assert %{"error" => %{"message" => message}} = json_response(conn, 422)
        assert message =~ "disposable" || message =~ "temporary"
      end
    end

    test "creates customer with valid data", %{conn: conn} do
      attrs = %{
        "name" => "Test Customer",
        "email" => "test#{System.unique_integer([:positive])}@testcompany.com"
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
        "email" => "test@testcompany.com"
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
      email = "duplicate#{System.unique_integer([:positive])}@testcompany.com"

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

    test "enforces rate limit (10 requests per minute per IP)", %{conn: conn} do
      # Make 10 successful requests
      for i <- 1..10 do
        attrs = %{
          "name" => "Test Customer #{i}",
          "email" => "test#{i}_#{System.unique_integer([:positive])}@testcompany.com"
        }

        conn =
          build_conn()
          |> put_req_header("x-forwarded-for", "192.168.1.100")
          |> post("/api/v1/customers/onboard", attrs)

        assert json_response(conn, 201)
      end

      # 11th request should be rate limited
      attrs = %{
        "name" => "Test Customer 11",
        "email" => "test11_#{System.unique_integer([:positive])}@testcompany.com"
      }

      conn =
        build_conn()
        |> put_req_header("x-forwarded-for", "192.168.1.100")
        |> post("/api/v1/customers/onboard", attrs)

      response = json_response(conn, 429)
      assert %{"error" => %{"message" => message, "code" => code}} = response
      assert code == "RATE_LIMITED"
      # Message contains "Rate limit exceeded" (capital R)
      assert message =~ "Rate limit" || message =~ "too many"
    end

    test "sets initial credit limits correctly", %{conn: conn} do
      attrs = %{
        "name" => "Test Customer",
        "email" => "test#{System.unique_integer([:positive])}@testcompany.com"
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
