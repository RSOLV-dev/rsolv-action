defmodule RsolvWeb.Api.V1.PhaseControllerTest do
  use RsolvWeb.ConnCase
  alias Rsolv.Phases.{Repository, ScanExecution, ValidationExecution}
  alias Rsolv.Customers.ForgeAccount
  alias Rsolv.Customers.{Customer, ApiKey}
  alias Rsolv.Repo

  describe "POST /api/v1/phases/store" do
    setup do
      # Create a customer with unique email for test isolation
      unique_email = "test-#{System.unique_integer([:positive])}@example.com"

      customer =
        %Customer{}
        |> Customer.changeset(%{
          name: "Test Corp",
          email: unique_email,
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

    test "stores scan phase data with unwrapped format", %{conn: conn, api_key: api_key} do
      conn =
        conn
        |> put_req_header("x-api-key", api_key.key)
        |> put_req_header("content-type", "application/json")
        |> post("/api/v1/phases/store", %{
          phase: "scan",
          repo: "RSOLV-dev/nodegoat-demo",
          commitSha: "abc123",
          branch: "main",
          data: %{
            vulnerabilities: [
              %{
                type: "xss",
                file: "app.js",
                line: 42,
                severity: "high"
              }
            ],
            timestamp: DateTime.utc_now()
          }
        })

      assert %{"success" => true, "id" => scan_id} = json_response(conn, 200)

      # Verify scan was stored with correct data
      scan = Repo.get!(ScanExecution, scan_id)
      assert scan.commit_sha == "abc123"
      assert scan.branch == "main"
      assert scan.vulnerabilities_count == 1
      assert length(scan.data["vulnerabilities"]) == 1
      assert scan.data["vulnerabilities"] |> hd() |> Map.get("type") == "xss"
    end

    test "stores validation phase data with unwrapped format", %{conn: conn, api_key: api_key} do
      conn =
        conn
        |> put_req_header("x-api-key", api_key.key)
        |> put_req_header("content-type", "application/json")
        |> post("/api/v1/phases/store", %{
          phase: "validation",
          repo: "RSOLV-dev/nodegoat-demo",
          issueNumber: 123,
          commitSha: "abc123",
          data: %{
            branchName: "rsolv/validate/issue-123",
            validated: true,
            generatedTests: %{
              success: true,
              testSuite: %{
                red: %{
                  testName: "should detect vulnerability",
                  testCode: "test('vulnerability', () => { expect(1).toBe(1); })",
                  attackVector: "'; DROP TABLE users; --",
                  expectedBehavior: "should_fail_on_vulnerable_code"
                }
              }
            }
          }
        })

      assert %{"success" => true, "id" => validation_id} = json_response(conn, 200)

      # Verify validation was stored with complete data
      validation = Repo.get!(ValidationExecution, validation_id)
      assert validation.issue_number == 123
      assert validation.validated == true
      assert validation.commit_sha == "abc123"
      assert validation.data["branchName"] == "rsolv/validate/issue-123"
      assert validation.data["generatedTests"]["success"] == true

      assert validation.data["generatedTests"]["testSuite"]["red"]["testName"] ==
               "should detect vulnerability"
    end

    test "stores mitigation phase data with unwrapped format", %{conn: conn, api_key: api_key} do
      conn =
        conn
        |> put_req_header("x-api-key", api_key.key)
        |> put_req_header("content-type", "application/json")
        |> post("/api/v1/phases/store", %{
          phase: "mitigation",
          repo: "RSOLV-dev/nodegoat-demo",
          issueNumber: 123,
          commitSha: "def456",
          data: %{
            prUrl: "https://github.com/RSOLV-dev/nodegoat-demo/pull/456",
            fixes: [
              %{
                file: "app.js",
                vulnerability: "xss",
                fixed: true
              }
            ],
            commitHash: "def456"
          }
        })

      assert %{"success" => true, "id" => mitigation_id} = json_response(conn, 200)

      # Verify mitigation was stored with correct data
      mitigation = Repo.get!(Rsolv.Phases.MitigationExecution, mitigation_id)
      assert mitigation.issue_number == 123
      assert mitigation.commit_sha == "def456"
      assert mitigation.data["pr_url"] == "https://github.com/RSOLV-dev/nodegoat-demo/pull/456"
      assert mitigation.data["pr_number"] == 456
      assert mitigation.data["files_changed"] == 1
    end

    test "rejects invalid API key", %{conn: conn} do
      conn =
        conn
        |> put_req_header("x-api-key", "invalid_key")
        |> put_req_header("content-type", "application/json")
        |> post("/api/v1/phases/store", %{
          phase: "scan",
          repo: "RSOLV-dev/test",
          commitSha: "abc123",
          data: %{}
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
        |> put_req_header("content-type", "application/json")
        |> post("/api/v1/phases/store", %{
          phase: "scan",
          # Customer doesn't own this namespace
          repo: "OTHER-org/test",
          commitSha: "abc123",
          data: %{}
        })

      assert %{"error" => "Unauthorized: no access to namespace"} = json_response(conn, 403)
    end

    test "validates required fields", %{conn: conn, api_key: api_key} do
      conn =
        conn
        |> put_req_header("x-api-key", api_key.key)
        |> put_req_header("content-type", "application/json")
        |> post("/api/v1/phases/store", %{
          phase: "scan",
          repo: "RSOLV-dev/test",
          # Missing commitSha
          data: %{}
        })

      assert %{"error" => _} = json_response(conn, 400)
    end

    test "auto-creates repository on first use", %{conn: conn, api_key: api_key} do
      # Verify repo doesn't exist
      assert nil ==
               Repo.get_by(Repository,
                 forge_type: :github,
                 namespace: "RSOLV-dev",
                 name: "new-repo"
               )

      conn =
        conn
        |> put_req_header("x-api-key", api_key.key)
        |> put_req_header("content-type", "application/json")
        |> post("/api/v1/phases/store", %{
          phase: "scan",
          repo: "RSOLV-dev/new-repo",
          commitSha: "abc123",
          data: %{scan: %{vulnerabilities: []}}
        })

      assert %{"success" => true} = json_response(conn, 200)

      # Verify repo was created
      repo =
        Repo.get_by(Repository,
          forge_type: :github,
          namespace: "RSOLV-dev",
          name: "new-repo"
        )

      assert repo != nil
      assert repo.full_path == "RSOLV-dev/new-repo"
    end

    test "uses the specific API key from authentication, not just any key for customer", %{
      customer: customer,
      forge_account: _forge_account
    } do
      # Create multiple API keys for the same customer
      api_key_1 =
        %ApiKey{}
        |> ApiKey.changeset(%{
          customer_id: customer.id,
          name: "First Key",
          key: "first_key_" <> Ecto.UUID.generate(),
          active: true
        })
        |> Repo.insert!()

      api_key_2 =
        %ApiKey{}
        |> ApiKey.changeset(%{
          customer_id: customer.id,
          name: "Second Key",
          key: "second_key_" <> Ecto.UUID.generate(),
          active: true
        })
        |> Repo.insert!()

      # Both keys share the same customer, so they share the forge account

      # Test with first API key
      conn =
        build_conn()
        |> put_req_header("x-api-key", api_key_1.key)
        |> put_req_header("content-type", "application/json")
        |> post("/api/v1/phases/store", %{
          phase: "scan",
          repo: "RSOLV-dev/specific-key-test",
          commitSha: "abc123",
          data: %{scan: %{vulnerabilities: []}}
        })

      assert %{"success" => true, "id" => scan_id_1} = json_response(conn, 200)

      # Verify the correct API key was used for storage
      scan_1 = Repo.get!(ScanExecution, scan_id_1)
      assert scan_1.api_key_id == api_key_1.id

      # Test with second API key
      conn =
        build_conn()
        |> put_req_header("x-api-key", api_key_2.key)
        |> put_req_header("content-type", "application/json")
        |> post("/api/v1/phases/store", %{
          phase: "scan",
          repo: "RSOLV-dev/specific-key-test-2",
          commitSha: "def456",
          data: %{scan: %{vulnerabilities: []}}
        })

      assert %{"success" => true, "id" => scan_id_2} = json_response(conn, 200)

      # Verify the correct API key was used for storage
      scan_2 = Repo.get!(ScanExecution, scan_id_2)
      assert scan_2.api_key_id == api_key_2.id

      # The key point: even though both API keys belong to the same customer,
      # the phase storage should use the specific API key that was used for authentication
      assert scan_1.api_key_id != scan_2.api_key_id
    end
  end
end
