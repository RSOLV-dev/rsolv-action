defmodule RsolvWeb.FixAttemptControllerTest do
  use RsolvWeb.ConnCase

  alias Rsolv.Billing.FixAttempt
  alias Rsolv.Repo

  describe "POST /api/v1/fix-attempts" do
    test "creates fix attempt with valid data", %{conn: conn} do
      attrs = %{
        github_org: "test-org",
        repo_name: "test-repo",
        issue_number: 123,
        pr_number: 456,
        pr_title: "[RSOLV] Fix authentication vulnerability",
        pr_url: "https://github.com/test-org/test-repo/pull/456",
        issue_title: "Security vulnerability in login",
        issue_url: "https://github.com/test-org/test-repo/issues/123",
        api_key_used: "rsolv_test_key_123",
        metadata: %{
          branch: "rsolv/123-fix-auth",
          labels: ["rsolv:automated", "security"],
          created_by: "rsolv-action"
        }
      }

      conn = post(conn, "/api/v1/fix-attempts", attrs)

      assert %{"id" => id, "status" => "pending"} = json_response(conn, 201)

      # Verify database record
      fix_attempt = Repo.get(FixAttempt, id)
      assert fix_attempt.github_org == "test-org"
      assert fix_attempt.repo_name == "test-repo"
      assert fix_attempt.issue_number == 123
      assert fix_attempt.pr_number == 456
      assert fix_attempt.status == "pending"
      assert fix_attempt.billing_status == "not_billed"
      assert fix_attempt.requires_manual_approval == true
    end

    test "creates fix attempt without issue number", %{conn: conn} do
      attrs = %{
        github_org: "test-org",
        repo_name: "test-repo",
        pr_number: 789,
        pr_title: "[RSOLV] Performance improvements",
        pr_url: "https://github.com/test-org/test-repo/pull/789",
        api_key_used: "rsolv_test_key_123",
        metadata: %{
          branch: "rsolv/perf-improvements",
          labels: ["rsolv:automated", "performance"],
          created_by: "rsolv-action"
        }
      }

      conn = post(conn, "/api/v1/fix-attempts", attrs)

      assert %{"id" => id, "status" => "pending"} = json_response(conn, 201)

      # Verify database record
      fix_attempt = Repo.get(FixAttempt, id)
      assert fix_attempt.github_org == "test-org"
      assert fix_attempt.repo_name == "test-repo"
      assert fix_attempt.issue_number == nil
      assert fix_attempt.pr_number == 789
    end

    test "returns error with missing required fields", %{conn: conn} do
      attrs = %{
        github_org: "test-org"
        # Missing required fields: repo_name and pr_number
        # status is set to default "pending"
      }

      conn = post(conn, "/api/v1/fix-attempts", attrs)

      assert %{"errors" => errors} = json_response(conn, 422)
      assert errors["repo_name"] == ["can't be blank"]
      assert errors["pr_number"] == ["can't be blank"]
      # status gets default value, so no error expected
    end

    test "prevents duplicate fix attempts for same PR", %{conn: conn} do
      # Create first fix attempt
      attrs = %{
        github_org: "test-org",
        repo_name: "test-repo",
        pr_number: 456,
        status: "pending"
      }

      conn1 = post(conn, "/api/v1/fix-attempts", attrs)
      assert json_response(conn1, 201)

      # Try to create duplicate
      conn2 = post(conn, "/api/v1/fix-attempts", attrs)
      assert %{"error" => error} = json_response(conn2, 409)
      assert error =~ "already exists"
    end
  end
end
