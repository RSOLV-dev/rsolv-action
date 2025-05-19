defmodule RSOLVWeb.CredentialControllerTest do
  use RSOLVWeb.ConnCase

  import RSOLV.Factory

  alias RSOLV.Accounts
  alias RSOLV.Credentials

  setup %{conn: conn} do
    # Create a test customer with valid subscription
    customer = insert(:customer, %{
      api_key: "rsolv_test_abc123",
      subscription_tier: "standard",
      monthly_limit: 100,
      current_usage: 15
    })

    {:ok, conn: put_req_header(conn, "accept", "application/json"), customer: customer}
  end

  describe "POST /api/v1/credentials/exchange" do
    test "exchanges valid API key for temporary credentials", %{conn: conn, customer: customer} do
      conn = post(conn, ~p"/api/v1/credentials/exchange", %{
        "api_key" => customer.api_key,
        "providers" => ["anthropic", "openai"],
        "ttl_minutes" => 60
      })

      assert json_response(conn, 200)
      assert %{
        "credentials" => credentials,
        "usage" => usage
      } = json_response(conn, 200)

      # Verify anthropic credentials
      assert %{
        "api_key" => "temp_ant_" <> _,
        "expires_at" => expires_at
      } = credentials["anthropic"]

      # Verify openai credentials  
      assert %{
        "api_key" => "temp_oai_" <> _,
        "expires_at" => expires_at
      } = credentials["openai"]

      # Verify usage information
      assert %{
        "remaining_fixes" => 85,
        "reset_at" => _
      } = usage

      # Verify expiration time is approximately 1 hour from now
      {:ok, expires_dt, _} = DateTime.from_iso8601(expires_at)
      assert DateTime.diff(expires_dt, DateTime.utc_now()) > 3500
      assert DateTime.diff(expires_dt, DateTime.utc_now()) < 3700
    end

    test "returns 401 for invalid API key", %{conn: conn} do
      conn = post(conn, ~p"/api/v1/credentials/exchange", %{
        "api_key" => "invalid_key",
        "providers" => ["anthropic"],
        "ttl_minutes" => 60
      })

      assert json_response(conn, 401)
      assert %{"error" => "Invalid API key"} = json_response(conn, 401)
    end

    test "returns 403 when usage limit exceeded", %{conn: conn, customer: customer} do
      # Update customer to have exceeded usage
      {:ok, _} = Accounts.update_customer(customer, %{current_usage: 100})

      conn = post(conn, ~p"/api/v1/credentials/exchange", %{
        "api_key" => customer.api_key,
        "providers" => ["anthropic"],
        "ttl_minutes" => 60
      })

      assert json_response(conn, 403)
      assert %{"error" => "Monthly usage limit exceeded"} = json_response(conn, 403)
    end

    test "returns 429 when rate limited", %{conn: conn, customer: customer} do
      # Make multiple rapid requests to trigger rate limit
      for _ <- 1..10 do
        post(conn, ~p"/api/v1/credentials/exchange", %{
          "api_key" => customer.api_key,
          "providers" => ["anthropic"],
          "ttl_minutes" => 60
        })
      end

      conn = post(conn, ~p"/api/v1/credentials/exchange", %{
        "api_key" => customer.api_key,
        "providers" => ["anthropic"],
        "ttl_minutes" => 60
      })

      assert json_response(conn, 429)
      assert %{"error" => "Rate limit exceeded", "retry_after" => _} = json_response(conn, 429)
    end

    test "validates required parameters", %{conn: conn} do
      conn = post(conn, ~p"/api/v1/credentials/exchange", %{})

      assert json_response(conn, 400)
      assert %{"error" => "Missing required parameters"} = json_response(conn, 400)
    end

    test "limits TTL to maximum value", %{conn: conn, customer: customer} do
      conn = post(conn, ~p"/api/v1/credentials/exchange", %{
        "api_key" => customer.api_key,
        "providers" => ["anthropic"],
        "ttl_minutes" => 1440  # 24 hours
      })

      assert json_response(conn, 200)
      credentials = json_response(conn, 200)["credentials"]
      
      # Verify TTL was capped at 4 hours
      {:ok, expires_dt, _} = DateTime.from_iso8601(credentials["anthropic"]["expires_at"])
      diff_hours = DateTime.diff(expires_dt, DateTime.utc_now()) / 3600
      assert diff_hours <= 4.1
    end

    test "tracks credential generation in database", %{conn: conn, customer: customer} do
      assert {:ok, initial_count} = Credentials.count_active_credentials(customer.id)

      post(conn, ~p"/api/v1/credentials/exchange", %{
        "api_key" => customer.api_key,
        "providers" => ["anthropic"],
        "ttl_minutes" => 60
      })

      assert {:ok, new_count} = Credentials.count_active_credentials(customer.id)
      assert new_count == initial_count + 1
    end

    test "includes GitHub job metadata when provided", %{conn: conn, customer: customer} do
      conn = conn
      |> put_req_header("x-github-job", "job_123")
      |> put_req_header("x-github-run", "run_456")
      |> post(~p"/api/v1/credentials/exchange", %{
        "api_key" => customer.api_key,
        "providers" => ["anthropic"],
        "ttl_minutes" => 60
      })

      assert json_response(conn, 200)
      
      # Verify metadata was stored
      credential = Credentials.get_latest_credential(customer.id)
      assert credential.github_job_id == "job_123"
      assert credential.github_run_id == "run_456"
    end
  end

  describe "POST /api/v1/credentials/refresh" do
    setup %{customer: customer} do
      # Create an existing credential
      {:ok, credential} = Credentials.create_temporary_credential(%{
        customer_id: customer.id,
        provider: "anthropic",
        expires_at: DateTime.add(DateTime.utc_now(), 300), # 5 minutes
        usage_limit: 100
      })

      {:ok, credential: credential}
    end

    test "refreshes expiring credential", %{conn: conn, customer: customer, credential: credential} do
      conn = post(conn, ~p"/api/v1/credentials/refresh", %{
        "api_key" => customer.api_key,
        "credential_id" => credential.id
      })

      assert json_response(conn, 200)
      assert %{
        "credentials" => %{
          "anthropic" => %{
            "api_key" => new_key,
            "expires_at" => new_expires
          }
        }
      } = json_response(conn, 200)

      # Verify new credential is different
      assert new_key != credential.encrypted_key

      # Verify new expiration is extended
      {:ok, new_expires_dt, _} = DateTime.from_iso8601(new_expires)
      assert DateTime.compare(new_expires_dt, credential.expires_at) == :gt
    end

    test "returns 404 for non-existent credential", %{conn: conn, customer: customer} do
      conn = post(conn, ~p"/api/v1/credentials/refresh", %{
        "api_key" => customer.api_key,
        "credential_id" => "nonexistent"
      })

      assert json_response(conn, 404)
      assert %{"error" => "Credential not found"} = json_response(conn, 404)
    end

    test "returns 403 for credential owned by another customer", %{conn: conn} do
      other_customer = insert(:customer)
      {:ok, credential} = Credentials.create_temporary_credential(%{
        customer_id: other_customer.id,
        provider: "anthropic",
        expires_at: DateTime.add(DateTime.utc_now(), 300)
      })

      conn = post(conn, ~p"/api/v1/credentials/refresh", %{
        "api_key" => "rsolv_test_abc123",
        "credential_id" => credential.id
      })

      assert json_response(conn, 403)
      assert %{"error" => "Access denied"} = json_response(conn, 403)
    end
  end

  describe "POST /api/v1/usage/report" do
    test "records usage metrics", %{conn: conn, customer: customer} do
      conn = post(conn, ~p"/api/v1/usage/report", %{
        "api_key" => customer.api_key,
        "provider" => "anthropic",
        "tokens_used" => 1500,
        "request_count" => 3,
        "job_id" => "gh_job_123"
      })

      assert json_response(conn, 200)
      assert %{"status" => "recorded"} = json_response(conn, 200)

      # Verify usage was recorded
      usage = Accounts.get_customer_usage(customer.id)
      assert usage.total_tokens >= 1500
      assert usage.total_requests >= 3
    end

    test "updates customer's current usage", %{conn: conn, customer: customer} do
      initial_usage = customer.current_usage

      post(conn, ~p"/api/v1/usage/report", %{
        "api_key" => customer.api_key,
        "provider" => "anthropic",
        "tokens_used" => 2000,
        "request_count" => 1,
        "job_id" => "gh_job_123"
      })

      updated_customer = Accounts.get_customer!(customer.id)
      # Assuming 1 fix per ~2000 tokens
      assert updated_customer.current_usage == initial_usage + 1
    end

    test "returns error for invalid API key", %{conn: conn} do
      conn = post(conn, ~p"/api/v1/usage/report", %{
        "api_key" => "invalid",
        "provider" => "anthropic",
        "tokens_used" => 1500,
        "request_count" => 1
      })

      assert json_response(conn, 401)
      assert %{"error" => "Invalid API key"} = json_response(conn, 401)
    end
  end
end