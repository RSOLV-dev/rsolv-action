defmodule Rsolv.Webhooks.EventRouterTest do
  use Rsolv.DataCase, async: true

  alias Rsolv.Webhooks.EventRouter
  alias Rsolv.Webhooks.Handlers.GitHubHandler

  describe "route_event/3" do
    test "routes GitHub pull request events to GitHub handler" do
      # First create a pending fix attempt
      alias Rsolv.Billing.FixAttempt

      {:ok, _fix_attempt} =
        %FixAttempt{}
        |> FixAttempt.changeset(%{
          github_org: "test-org",
          repo_name: "test-repo",
          issue_number: 10,
          pr_number: 42,
          status: "pending"
        })
        |> Repo.insert()

      payload = %{
        "action" => "closed",
        "pull_request" => %{
          "id" => 123,
          "merged" => true,
          "number" => 42,
          "base" => %{"repo" => %{"name" => "test-repo", "owner" => %{"login" => "test-org"}}}
        }
      }

      headers = [{"x-github-event", "pull_request"}]

      assert {:ok, :merged} = EventRouter.route_event("github", headers, payload)
    end

    test "routes GitHub issue events to GitHub handler" do
      payload = %{
        "action" => "closed",
        "issue" => %{
          "id" => 456,
          "number" => 10,
          "state" => "closed"
        }
      }

      headers = [{"x-github-event", "issues"}]

      assert {:ok, :issue_closed} = EventRouter.route_event("github", headers, payload)
    end

    test "returns error for unsupported platform" do
      payload = %{}
      headers = []

      assert {:error, :unsupported_platform} =
               EventRouter.route_event("bitbucket", headers, payload)
    end

    test "returns error for unknown GitHub event type" do
      payload = %{}
      headers = [{"x-github-event", "unknown_event"}]

      assert {:error, :unsupported_event} = EventRouter.route_event("github", headers, payload)
    end

    test "handles GitLab events (future implementation)" do
      payload = %{}
      headers = [{"x-gitlab-event", "Merge Request Hook"}]

      assert {:error, :platform_not_implemented} =
               EventRouter.route_event("gitlab", headers, payload)
    end
  end

  describe "verify_signature/3" do
    test "verifies GitHub webhook signature" do
      secret = "test_secret"
      payload = ~s({"test": "data"})

      signature =
        "sha256=" <> Base.encode16(:crypto.mac(:hmac, :sha256, secret, payload), case: :lower)

      assert :ok = EventRouter.verify_signature("github", signature, payload, secret)
    end

    test "rejects invalid GitHub signature" do
      secret = "test_secret"
      payload = ~s({"test": "data"})
      invalid_signature = "sha256=invalid"

      assert {:error, :invalid_signature} =
               EventRouter.verify_signature("github", invalid_signature, payload, secret)
    end

    test "handles missing signature" do
      assert {:error, :missing_signature} =
               EventRouter.verify_signature("github", nil, "{}", "secret")
    end
  end

  describe "extract_platform/1" do
    test "identifies GitHub from headers" do
      headers = [{"x-github-event", "push"}, {"user-agent", "GitHub-Hookshot/abc123"}]
      assert "github" = EventRouter.extract_platform(headers)
    end

    test "identifies GitLab from headers" do
      headers = [{"x-gitlab-event", "Push Hook"}]
      assert "gitlab" = EventRouter.extract_platform(headers)
    end

    test "returns unknown for unidentified platform" do
      headers = [{"content-type", "application/json"}]
      assert "unknown" = EventRouter.extract_platform(headers)
    end
  end
end
