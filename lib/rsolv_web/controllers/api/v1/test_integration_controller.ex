defmodule RsolvWeb.Api.V1.TestIntegrationController do
  @moduledoc """
  API controller for test integration helper endpoints.

  RFC-060-AMENDMENT-001: Helper APIs for test file naming and analysis.
  Created: 2025-10-13

  Provides endpoints for:
  - Semantic test file naming based on vulnerability type and framework
  - Test file scoring and recommendations (future)
  - AST-based test integration (future)
  """

  use RsolvWeb, :controller
  alias Rsolv.TestIntegration.Naming

  plug RsolvWeb.Plugs.ApiAuthentication

  action_fallback RsolvWeb.FallbackController

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

  defp validate_naming_params(params) do
    vulnerable_file = params["vulnerableFile"] || params[:vulnerableFile]
    type = params["type"] || params[:type]
    framework = params["framework"] || params[:framework]

    cond do
      is_nil(vulnerable_file) or vulnerable_file == "" ->
        {:error, :vulnerable_file_required}

      is_nil(type) or type == "" ->
        {:error, :type_required}

      is_nil(framework) or framework == "" ->
        {:error, :framework_required}

      true ->
        {:ok, %{
          vulnerable_file: vulnerable_file,
          type: type,
          framework: String.downcase(framework)
        }}
    end
  end

  defp generate_test_name(%{vulnerable_file: file, type: type, framework: framework}) do
    Naming.generate_test_name(file, type, framework)
  end
end
