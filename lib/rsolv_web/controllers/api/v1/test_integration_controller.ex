defmodule RsolvWeb.Api.V1.TestIntegrationController do
  @moduledoc """
  Controller for test integration endpoints.

  RFC-060-AMENDMENT-001: Test integration APIs for AST-based test integration
  and helper endpoints for semantic naming.

  Provides endpoints for:
  - AST-based test integration into existing test files
  - Semantic test file naming based on vulnerability type and framework

  ## Security

  - Requires API authentication via ApiAuthentication plug
  - Rate limited per customer
  """

  use RsolvWeb, :controller

  alias Rsolv.AST.TestIntegrator
  alias Rsolv.RateLimiter
  alias Rsolv.TestIntegration.Naming

  require Logger

  plug RsolvWeb.Plugs.ApiAuthentication

  action_fallback RsolvWeb.FallbackController

  @supported_frameworks ~w(vitest jest mocha)
  @supported_languages ~w(javascript typescript)

  @doc """
  Generate integrated test file content using AST manipulation.

  ## Request Body

      {
        "targetFileContent": "describe('UsersController', () => { ... })",
        "testSuite": {
          "redTests": [{
            "testName": "rejects SQL injection in search endpoint",
            "testCode": "post('/search', { q: \"admin'; DROP TABLE users;--\" })\\nexpect(response.status).toBe(400)",
            "attackVector": "admin'; DROP TABLE users;--",
            "expectedBehavior": "should_fail_on_vulnerable_code",
            "vulnerableCodePath": "app/controllers/users_controller.js:42",
            "vulnerablePattern": "db.query(`SELECT * FROM users WHERE name LIKE '%${req.query.q}%'`)"
          }]
        },
        "framework": "vitest",
        "language": "javascript"
      }

  ## Response

      {
        "integratedContent": "describe('UsersController', () => { ... new test ... })",
        "method": "ast",
        "insertionPoint": {
          "line": 42,
          "strategy": "after_last_it_block"
        }
      }

  ## Error Responses

  - 400: Invalid request (missing required fields)
  - 401: Authentication failed
  - 429: Rate limit exceeded
  - 422: Integration failed
  - 500: Internal error
  """
  def generate(conn, params) do
    start_time = System.monotonic_time(:millisecond)
    request_id = params["requestId"] || generate_request_id()
    customer = conn.assigns.customer

    Logger.info("TestIntegrationController: Received generate request from customer #{customer.id}")

    with :ok <- check_rate_limit(customer),
         :ok <- validate_generate_request(params),
         {:ok, integrated_content, insertion_point, method} <-
           TestIntegrator.generate_integration(
             params["targetFileContent"],
             params["testSuite"],
             params["language"],
             params["framework"]
           ) do
      total_time = System.monotonic_time(:millisecond) - start_time
      Logger.info("TestIntegrationController: Successfully generated integration (method: #{method}, time: #{total_time}ms)")

      json(conn, %{
        requestId: request_id,
        integratedContent: integrated_content,
        method: method,
        insertionPoint: insertion_point,
        timing: %{totalTimeMs: total_time}
      })
    else
      error -> handle_generate_error(conn, error, request_id)
    end
  end

  @doc """
  Generate semantic test file name based on vulnerability and framework.

  ## Request Parameters
  - `vulnerableFile` (required): Path to the vulnerable file
  - `type` (required): Vulnerability type (e.g., "sql_injection", "xss")
  - `framework` (required): Test framework (e.g., "rspec", "vitest", "pytest")

  ## Response
  ```json
  {
    "testFileName": "users_sql_injection_spec.rb",
    "testPath": "spec/security/users_sql_injection_spec.rb"
  }
  ```

  ## Examples

      # RSpec (Ruby)
      POST /api/v1/test-integration/naming
      {
        "vulnerableFile": "app/controllers/users_controller.rb",
        "type": "sql_injection",
        "framework": "rspec"
      }
      => {
        "testFileName": "users_controller_sql_injection_spec.rb",
        "testPath": "spec/security/users_controller_sql_injection_spec.rb"
      }

      # Vitest (TypeScript)
      POST /api/v1/test-integration/naming
      {
        "vulnerableFile": "src/controllers/UsersController.ts",
        "type": "sql_injection",
        "framework": "vitest"
      }
      => {
        "testFileName": "UsersController.sqlInjection.test.ts",
        "testPath": "__tests__/security/UsersController.sqlInjection.test.ts"
      }

      # pytest (Python)
      POST /api/v1/test-integration/naming
      {
        "vulnerableFile": "app/controllers/users_controller.py",
        "type": "sql_injection",
        "framework": "pytest"
      }
      => {
        "testFileName": "test_sql_injection_users_controller.py",
        "testPath": "tests/security/test_sql_injection_users_controller.py"
      }
  """
  def naming(conn, params) do
    with {:ok, validated_params} <- validate_naming_params(params),
         result <- generate_test_name(validated_params) do
      json(conn, result)
    end
  end

  # Private functions

  defp handle_generate_error(conn, error, request_id) do
    case error do
      {:error, :rate_limited} ->
        send_error_response(conn, 429, "RATE_LIMITED",
          "Rate limit exceeded. Please try again later.",
          request_id, %{retryAfter: 60})

      {:error, {:validation, message}} ->
        send_error_response(conn, 400, "INVALID_REQUEST", message, request_id)

      {:error, {:unsupported_framework, framework}} ->
        send_error_response(conn, 422, "UNSUPPORTED_FRAMEWORK",
          "Framework '#{framework}' is not supported. Supported: #{Enum.join(@supported_frameworks, ", ")}",
          request_id)

      {:error, reason} ->
        Logger.error("TestIntegrationController: Integration failed: #{inspect(reason)}")
        send_error_response(conn, 500, "INTEGRATION_FAILED",
          "Failed to integrate test", request_id)
    end
  end

  defp send_error_response(conn, status, code, message, request_id, extra \\ %{}) do
    conn
    |> maybe_add_retry_after(status)
    |> put_status(status)
    |> json(Map.merge(%{
      error: %{code: code, message: message},
      requestId: request_id
    }, extra))
  end

  defp maybe_add_retry_after(conn, 429), do: put_resp_header(conn, "retry-after", "60")
  defp maybe_add_retry_after(conn, _), do: conn

  defp check_rate_limit(customer) do
    case RateLimiter.check_rate_limit(customer.id, "test_integration") do
      :ok -> :ok
      {:error, _} -> {:error, :rate_limited}
    end
  end

  defp validate_generate_request(params) do
    with :ok <- validate_required_fields(params, ~w(targetFileContent testSuite framework language)),
         :ok <- validate_field_type(params["targetFileContent"], :binary, "targetFileContent"),
         :ok <- validate_field_type(params["testSuite"], :map, "testSuite"),
         :ok <- validate_field_type(params["testSuite"]["redTests"], :list, "testSuite.redTests"),
         :ok <- validate_not_empty(params["testSuite"]["redTests"], "testSuite.redTests"),
         :ok <- validate_enum(params["framework"], @supported_frameworks, "framework"),
         :ok <- validate_enum(params["language"], @supported_languages, "language") do
      validate_test_suite_structure(params["testSuite"])
    end
  end

  defp validate_required_fields(params, required_fields) do
    missing = required_fields -- Map.keys(params)
    if Enum.empty?(missing),
      do: :ok,
      else: {:error, {:validation, "Missing required fields: #{Enum.join(missing, ", ")}"}}
  end

  defp validate_field_type(value, :binary, _field) when is_binary(value), do: :ok
  defp validate_field_type(value, :map, _field) when is_map(value), do: :ok
  defp validate_field_type(value, :list, _field) when is_list(value), do: :ok
  defp validate_field_type(_value, type, field) do
    type_name = type |> to_string() |> String.replace("_", " ")
    {:error, {:validation, "#{field} must be a #{type_name}"}}
  end

  defp validate_not_empty(list, _field) when is_list(list) and length(list) > 0, do: :ok
  defp validate_not_empty(_, field), do: {:error, {:validation, "#{field} must not be empty"}}

  defp validate_enum(value, allowed, field) do
    if value in allowed do
      :ok
    else
      {:error, {:validation, "#{field} must be one of: #{Enum.join(allowed, ", ")}"}}
    end
  end

  defp validate_test_suite_structure(%{"redTests" => red_tests}) do
    required_test_fields = ~w(testName testCode attackVector)

    red_tests
    |> Enum.find(fn test ->
      not Enum.empty?(required_test_fields -- Map.keys(test))
    end)
    |> case do
      nil -> :ok
      test ->
        missing = required_test_fields -- Map.keys(test)
        {:error, {:validation, "Test missing required fields: #{Enum.join(missing, ", ")}"}}
    end
  end

  defp validate_naming_params(params) do
    with {:ok, vulnerable_file} <- extract_param(params, "vulnerableFile", :vulnerableFile),
         {:ok, type} <- extract_param(params, "type", :type),
         {:ok, framework} <- extract_param(params, "framework", :framework) do
      {:ok, %{
        vulnerable_file: vulnerable_file,
        type: type,
        framework: String.downcase(framework)
      }}
    end
  end

  defp extract_param(params, string_key, atom_key) do
    case params[string_key] || params[atom_key] do
      nil -> {:error, :"#{atom_key}_required"}
      "" -> {:error, :"#{atom_key}_required"}
      value -> {:ok, value}
    end
  end

  defp generate_test_name(%{vulnerable_file: file, type: type, framework: framework}),
    do: Naming.generate_test_name(file, type, framework)

  defp generate_request_id,
    do: "test-int-#{System.system_time(:millisecond)}-#{:rand.uniform(999999)}"
end
