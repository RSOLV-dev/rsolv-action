defmodule RsolvWeb.Api.V1.TestIntegrationController do
  @moduledoc """
  REST API controller for test file integration analysis.

  RFC-060-AMENDMENT-001: Provides endpoints for:
  1. Analyzing test files to find best integration point (score candidates)
  2. Generating integrated test files using AST manipulation

  ## Security

  - Requires API authentication via RsolvWeb.Plugs.ApiAuthentication
  - Rate limited per customer
  - No customer code is stored - all operations are stateless

  ## Endpoints

  - POST /api/v1/test-integration/analyze - Score test file candidates
  - POST /api/v1/test-integration/generate - Integrate test into target file (TODO: Phase 1 Part 2)
  """

  use RsolvWeb, :controller

  alias Rsolv.AST.TestScorer
  alias Rsolv.RateLimiter

  require Logger

  plug RsolvWeb.Plugs.ApiAuthentication

  @doc """
  Analyzes test file candidates and returns scored recommendations.

  ## Request Body

  ```json
  {
    "vulnerableFile": "app/controllers/users_controller.rb",
    "vulnerabilityType": "sql_injection",
    "candidateTestFiles": [
      "spec/controllers/users_controller_spec.rb",
      "spec/requests/users_spec.rb"
    ],
    "framework": "rspec"
  }
  ```

  ## Response

  ```json
  {
    "recommendations": [
      {
        "path": "spec/controllers/users_controller_spec.rb",
        "score": 1.5,
        "reason": "Direct unit test for vulnerable controller"
      }
    ],
    "fallback": {
      "path": "spec/security/users_controller_security_spec.rb",
      "reason": "No existing test found"
    }
  }
  ```
  """
  def analyze(conn, params) do
    customer = conn.assigns.customer

    with :ok <- check_rate_limit(customer),
         {:ok, request} <- validate_analyze_request(params) do
      # Score test files using TestScorer
      result =
        TestScorer.score_test_files(
          request["vulnerableFile"],
          request["candidateTestFiles"],
          request["framework"]
        )

      json(conn, result)
    else
      {:error, :rate_limited} ->
        conn
        |> put_resp_header("retry-after", "60")
        |> put_status(429)
        |> json(%{
          error: %{
            code: "RATE_LIMITED",
            message: "Rate limit exceeded. Please try again later."
          },
          retryAfter: 60
        })

      {:error, {:validation, message}} ->
        conn
        |> put_status(400)
        |> json(%{
          error: %{
            code: "INVALID_REQUEST",
            message: message
          }
        })

      {:error, reason} ->
        Logger.error("Test integration analysis error: #{inspect(reason)}")

        conn
        |> put_status(500)
        |> json(%{
          error: %{
            code: "INTERNAL_ERROR",
            message: "Analysis failed"
          }
        })
    end
  end

  @doc """
  Generates integrated test file content using AST manipulation.

  TODO: Implement in Phase 1 Part 2 (AST Integration)

  ## Request Body

  ```json
  {
    "targetFileContent": "describe UsersController do\\n  it 'creates user' do\\n  end\\nend",
    "testSuite": {
      "redTests": [{
        "testName": "rejects SQL injection in search endpoint",
        "testCode": "post :search, params: { q: \\"admin'; DROP TABLE users;--\\" }\\nexpect(response.status).to eq(400)",
        "attackVector": "admin'; DROP TABLE users;--",
        "expectedBehavior": "should_fail_on_vulnerable_code"
      }]
    },
    "framework": "rspec",
    "language": "ruby"
  }
  ```

  ## Response

  ```json
  {
    "integratedContent": "describe UsersController do\\n  # ... integrated test ...\\nend",
    "method": "ast",
    "insertionPoint": {
      "line": 5,
      "strategy": "after_last_it_block"
    }
  }
  ```
  """
  def generate(conn, _params) do
    # TODO: Implement AST integration in Phase 1 Part 2
    conn
    |> put_status(501)
    |> json(%{
      error: %{
        code: "NOT_IMPLEMENTED",
        message: "AST integration endpoint will be implemented in Phase 1 Part 2"
      }
    })
  end

  # Private helper functions

  defp check_rate_limit(customer) do
    RateLimiter.check_rate_limit(customer.id, "test_integration")
  end

  defp validate_analyze_request(params) do
    with :ok <- validate_required_fields(params, ["vulnerableFile", "candidateTestFiles", "framework"]),
         :ok <- validate_candidate_files(params["candidateTestFiles"]),
         :ok <- validate_framework(params["framework"]) do
      {:ok, params}
    end
  end

  defp validate_required_fields(params, required_fields) do
    case required_fields -- Map.keys(params) do
      [] -> :ok
      missing -> {:error, {:validation, "missing required fields: #{Enum.join(missing, ", ")}"}}
    end
  end

  defp validate_candidate_files(nil), do: {:error, {:validation, "candidateTestFiles required"}}
  defp validate_candidate_files([]), do: {:error, {:validation, "at least one candidate test file required"}}
  defp validate_candidate_files(files) when not is_list(files), do: {:error, {:validation, "candidateTestFiles must be an array"}}

  defp validate_candidate_files(files) when is_list(files) do
    if Enum.all?(files, &is_binary/1),
      do: :ok,
      else: {:error, {:validation, "candidateTestFiles must be an array of strings"}}
  end

  @supported_frameworks ["rspec", "vitest", "jest", "pytest", "mocha", "minitest"]

  defp validate_framework(framework) when framework in @supported_frameworks, do: :ok
  defp validate_framework(nil), do: {:error, {:validation, "framework required"}}
  defp validate_framework(framework) when not is_binary(framework), do: {:error, {:validation, "framework must be a string"}}

  defp validate_framework(framework) when is_binary(framework) do
    supported_list = Enum.join(@supported_frameworks, ", ")
    {:error, {:validation, "unsupported framework: #{framework}. Supported: #{supported_list}"}}
  end
end
