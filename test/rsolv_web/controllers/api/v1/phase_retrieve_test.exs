defmodule RsolvWeb.Api.V1.PhaseRetrieveTest do
  use RsolvWeb.ConnCase
  import Rsolv.TestHelpers, only: [unique_email: 0, unique_email: 1]
  alias Rsolv.Phases
  alias Rsolv.Phases.Repository
  alias Rsolv.Customers.{Customer, ApiKey, ForgeAccount}
  alias Rsolv.Repo

  describe "GET /api/v1/phases/retrieve" do
    setup do
      # Create a customer directly
      customer =
        %Customer{}
        |> Customer.changeset(%{
          name: "Test Corp",
          email: unique_email(),
          active: true
        })
        |> Repo.insert!()

      # Create an API key
      api_key =
        %ApiKey{}
        |> ApiKey.changeset(%{
          customer_id: customer.id,
          name: "Test Key",
          key: "test_" <> Ecto.UUID.generate(),
          active: true
        })
        |> Repo.insert!()

      # Create a forge account for this customer
      forge_account =
        %ForgeAccount{}
        |> ForgeAccount.changeset(%{
          customer_id: customer.id,
          forge_type: :github,
          namespace: "RSOLV-dev",
          verified_at: DateTime.utc_now()
        })
        |> Repo.insert!()

      %{api_key: api_key, customer: customer, forge_account: forge_account}
    end

    test "retrieves all phase data for a repository", %{conn: conn, api_key: api_key} do
      # Store scan data
      {:ok, _scan} =
        Phases.store_scan(
          %{
            repo: "RSOLV-dev/nodegoat-demo",
            commit_sha: "abc123",
            branch: "main",
            data: %{
              "vulnerabilities" => [
                %{"type" => "xss", "file" => "app.js", "line" => 42}
              ]
            }
          },
          api_key
        )

      # Store validation data
      {:ok, _validation} =
        Phases.store_validation(
          %{
            repo: "RSOLV-dev/nodegoat-demo",
            issue_number: 123,
            commit_sha: "abc123",
            data: %{
              "validated" => true,
              "confidence" => 0.95
            }
          },
          api_key
        )

      # Store mitigation data
      {:ok, _mitigation} =
        Phases.store_mitigation(
          %{
            repo: "RSOLV-dev/nodegoat-demo",
            issue_number: 123,
            commit_sha: "def456",
            data: %{
              "pr_url" => "https://github.com/RSOLV-dev/nodegoat-demo/pull/456",
              "fixes" => [
                %{"file" => "app.js", "fixed" => true}
              ]
            }
          },
          api_key
        )

      # Retrieve all phase data
      conn =
        conn
        |> put_req_header("x-api-key", api_key.key)
        |> get("/api/v1/phases/retrieve", %{
          repo: "RSOLV-dev/nodegoat-demo",
          issue: 123,
          commit: "abc123"
        })

      response = json_response(conn, 200)

      # Verify scan data
      assert response["scan"]
      assert response["scan"]["vulnerabilities"]
      assert length(response["scan"]["vulnerabilities"]) == 1

      # Verify validation data
      assert response["validation"]
      assert response["validation"]["issue-123"]["validated"] == true
      assert response["validation"]["issue-123"]["confidence"] == 0.95

      # Verify mitigation data (latest commit)
      assert response["mitigation"]
      assert response["mitigation"]["issue-123"]["pr_url"]
    end

    test "returns empty object when no data exists", %{conn: conn, api_key: api_key} do
      conn =
        conn
        |> put_req_header("x-api-key", api_key.key)
        |> get("/api/v1/phases/retrieve", %{
          repo: "RSOLV-dev/new-repo",
          issue: 999,
          commit: "xyz789"
        })

      response = json_response(conn, 200)

      assert response == %{}
    end

    test "returns only available phases", %{conn: conn, api_key: api_key} do
      # Store only scan data
      {:ok, _scan} =
        Phases.store_scan(
          %{
            repo: "RSOLV-dev/partial-repo",
            commit_sha: "partial123",
            branch: "main",
            data: %{
              "vulnerabilities" => [
                %{"type" => "sql_injection", "severity" => "high"}
              ]
            }
          },
          api_key
        )

      conn =
        conn
        |> put_req_header("x-api-key", api_key.key)
        |> get("/api/v1/phases/retrieve", %{
          repo: "RSOLV-dev/partial-repo",
          issue: 456,
          commit: "partial123"
        })

      response = json_response(conn, 200)

      # Should have scan but not validation or mitigation
      assert response["scan"]
      assert response["scan"]["vulnerabilities"]
      refute response["validation"]
      refute response["mitigation"]
    end

    test "rejects invalid API key", %{conn: conn} do
      conn =
        conn
        |> put_req_header("x-api-key", "invalid_key")
        |> get("/api/v1/phases/retrieve", %{
          repo: "RSOLV-dev/test",
          issue: 123,
          commit: "abc123"
        })

      resp = json_response(conn, 401)
      assert resp["error"]["code"] == "INVALID_API_KEY"
      assert resp["error"]["message"] == "Invalid or expired API key"
      assert resp["requestId"]
    end

    test "rejects access to unauthorized namespace", %{conn: conn, api_key: api_key} do
      conn =
        conn
        |> put_req_header("x-api-key", api_key.key)
        |> get("/api/v1/phases/retrieve", %{
          repo: "OTHER-org/test",
          issue: 123,
          commit: "abc123"
        })

      assert %{"error" => "Unauthorized: no access to namespace"} = json_response(conn, 403)
    end

    test "validates required parameters", %{conn: conn, api_key: api_key} do
      conn =
        conn
        |> put_req_header("x-api-key", api_key.key)
        |> get("/api/v1/phases/retrieve", %{
          repo: "RSOLV-dev/test"
          # Missing issue and commit
        })

      assert %{"error" => _} = json_response(conn, 400)
    end
  end
end
