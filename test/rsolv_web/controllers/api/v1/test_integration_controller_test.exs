defmodule RsolvWeb.Api.V1.TestIntegrationControllerTest do
  @moduledoc """
  Tests for test integration API endpoints.

  RFC-060-AMENDMENT-001: Phase 1-Backend - Semantic naming helper API
  Created: 2025-10-13

  Tests cover:
  - Authentication requirements
  - Parameter validation
  - Successful naming generation
  - Error handling
  """
  use RsolvWeb.ConnCase
  import Rsolv.APITestHelpers

  setup do
    # Create customer and API key for authenticated requests
    setup_api_auth()
  end

  describe "POST /api/v1/test-integration/naming" do
    test "requires authentication", %{conn: conn} do
      # Send request without API key
      conn = post(conn, "/api/v1/test-integration/naming", %{
        vulnerableFile: "app/model.rb",
        type: "sql_injection",
        framework: "rspec"
      })

      assert json_response(conn, 401)
    end

    test "generates RSpec test name for Ruby file", %{conn: conn, api_key: api_key} do
      conn = conn
        |> put_req_header("x-api-key", api_key.key)
        |> post("/api/v1/test-integration/naming", %{
        vulnerableFile: "app/controllers/users_controller.rb",
        type: "sql_injection",
        framework: "rspec"
      })

      assert %{
        "testFileName" => "users_controller_sql_injection_spec.rb",
        "testPath" => "spec/security/users_controller_sql_injection_spec.rb"
      } = json_response(conn, 200)
    end

    test "generates Jest test name for TypeScript file", %{conn: conn, api_key: api_key} do
      conn = conn
        |> put_req_header("x-api-key", api_key.key)
        |> post("/api/v1/test-integration/naming", %{
        vulnerableFile: "src/api/AuthService.ts",
        type: "jwt_weak_secret",
        framework: "jest"
      })

      assert %{
        "testFileName" => "AuthService.jwtWeakSecret.test.ts",
        "testPath" => "__tests__/security/AuthService.jwtWeakSecret.test.ts"
      } = json_response(conn, 200)
    end

    test "generates Vitest test name for JavaScript file", %{conn: conn, api_key: api_key} do
      conn = conn
        |> put_req_header("x-api-key", api_key.key)
        |> post("/api/v1/test-integration/naming", %{
        vulnerableFile: "src/controllers/users_controller.js",
        type: "xss_reflected",
        framework: "vitest"
      })

      assert %{
        "testFileName" => "UsersController.xssReflected.test.js",
        "testPath" => "__tests__/security/UsersController.xssReflected.test.js"
      } = json_response(conn, 200)
    end

    test "generates pytest test name for Python file", %{conn: conn, api_key: api_key} do
      conn = conn
        |> put_req_header("x-api-key", api_key.key)
        |> post("/api/v1/test-integration/naming", %{
        vulnerableFile: "app/services/payment.py",
        type: "command_injection",
        framework: "pytest"
      })

      assert %{
        "testFileName" => "test_command_injection_payment.py",
        "testPath" => "tests/security/test_command_injection_payment.py"
      } = json_response(conn, 200)
    end

    test "handles framework name case-insensitively", %{conn: conn, api_key: api_key} do
      conn = conn |> put_req_header("x-api-key", api_key.key)
      conn = post(conn, "/api/v1/test-integration/naming", %{
        vulnerableFile: "app/model.rb",
        type: "sql_injection",
        framework: "RSPEC"  # Uppercase
      })

      assert %{
        "testFileName" => "model_sql_injection_spec.rb",
        "testPath" => "spec/security/model_sql_injection_spec.rb"
      } = json_response(conn, 200)
    end

    test "returns error when vulnerableFile is missing", %{conn: conn, api_key: api_key} do
      conn = conn |> put_req_header("x-api-key", api_key.key)
      conn = post(conn, "/api/v1/test-integration/naming", %{
        type: "sql_injection",
        framework: "rspec"
      })

      assert %{"error" => _} = json_response(conn, 422)
    end

    test "returns error when type is missing", %{conn: conn, api_key: api_key} do
      conn = conn |> put_req_header("x-api-key", api_key.key)
      conn = post(conn, "/api/v1/test-integration/naming", %{
        vulnerableFile: "app/model.rb",
        framework: "rspec"
      })

      assert %{"error" => _} = json_response(conn, 422)
    end

    test "returns error when framework is missing", %{conn: conn, api_key: api_key} do
      conn = conn |> put_req_header("x-api-key", api_key.key)
      conn = post(conn, "/api/v1/test-integration/naming", %{
        vulnerableFile: "app/model.rb",
        type: "sql_injection"
      })

      assert %{"error" => _} = json_response(conn, 422)
    end

    test "returns error when vulnerableFile is empty string", %{conn: conn, api_key: api_key} do
      conn = conn |> put_req_header("x-api-key", api_key.key)
      conn = post(conn, "/api/v1/test-integration/naming", %{
        vulnerableFile: "",
        type: "sql_injection",
        framework: "rspec"
      })

      assert %{"error" => _} = json_response(conn, 422)
    end

    test "handles complex file paths", %{conn: conn, api_key: api_key} do
      conn = conn |> put_req_header("x-api-key", api_key.key)
      conn = post(conn, "/api/v1/test-integration/naming", %{
        vulnerableFile: "app/controllers/api/v1/admin/users_controller.rb",
        type: "authorization_bypass",
        framework: "rspec"
      })

      assert %{
        "testFileName" => "users_controller_authorization_bypass_spec.rb",
        "testPath" => "spec/security/users_controller_authorization_bypass_spec.rb"
      } = json_response(conn, 200)
    end

    test "handles vulnerability types with special characters", %{conn: conn, api_key: api_key} do
      conn = conn |> put_req_header("x-api-key", api_key.key)
      conn = post(conn, "/api/v1/test-integration/naming", %{
        vulnerableFile: "src/api/Auth.ts",
        type: "jwt-weak-secret",  # Hyphenated
        framework: "jest"
      })

      response = json_response(conn, 200)
      assert response["testFileName"] =~ "jwtWeakSecret"
    end

    test "works with mocha framework", %{conn: conn, api_key: api_key} do
      conn = conn |> put_req_header("x-api-key", api_key.key)
      conn = post(conn, "/api/v1/test-integration/naming", %{
        vulnerableFile: "src/utils/validator.js",
        type: "regex_dos",
        framework: "mocha"
      })

      assert %{
        "testFileName" => "Validator.regexDos.test.js",
        "testPath" => "__tests__/security/Validator.regexDos.test.js"
      } = json_response(conn, 200)
    end

    test "works with minitest framework", %{conn: conn, api_key: api_key} do
      conn = conn |> put_req_header("x-api-key", api_key.key)
      conn = post(conn, "/api/v1/test-integration/naming", %{
        vulnerableFile: "lib/auth.rb",
        type: "weak_password",
        framework: "minitest"
      })

      assert %{
        "testFileName" => "auth_weak_password_spec.rb",
        "testPath" => "spec/security/auth_weak_password_spec.rb"
      } = json_response(conn, 200)
    end

    test "works with unittest framework", %{conn: conn, api_key: api_key} do
      conn = conn |> put_req_header("x-api-key", api_key.key)
      conn = post(conn, "/api/v1/test-integration/naming", %{
        vulnerableFile: "lib/crypto.py",
        type: "weak_encryption",
        framework: "unittest"
      })

      assert %{
        "testFileName" => "test_weak_encryption_crypto.py",
        "testPath" => "tests/security/test_weak_encryption_crypto.py"
      } = json_response(conn, 200)
    end
  end

  describe "real-world vulnerability scenarios" do
    test "SQL injection in Rails API controller", %{conn: conn, api_key: api_key} do
      conn = conn |> put_req_header("x-api-key", api_key.key)
      conn = post(conn, "/api/v1/test-integration/naming", %{
        vulnerableFile: "app/controllers/api/v1/search_controller.rb",
        type: "sql_injection",
        framework: "rspec"
      })

      assert %{
        "testFileName" => "search_controller_sql_injection_spec.rb",
        "testPath" => "spec/security/search_controller_sql_injection_spec.rb"
      } = json_response(conn, 200)
    end

    test "XSS in React component", %{conn: conn, api_key: api_key} do
      conn = conn |> put_req_header("x-api-key", api_key.key)
      conn = post(conn, "/api/v1/test-integration/naming", %{
        vulnerableFile: "src/components/UserProfile.tsx",
        type: "xss_reflected",
        framework: "vitest"
      })

      assert %{
        "testFileName" => "UserProfile.xssReflected.test.tsx",
        "testPath" => "__tests__/security/UserProfile.xssReflected.test.tsx"
      } = json_response(conn, 200)
    end

    test "Command injection in Python utility", %{conn: conn, api_key: api_key} do
      conn = conn |> put_req_header("x-api-key", api_key.key)
      conn = post(conn, "/api/v1/test-integration/naming", %{
        vulnerableFile: "app/utils/file_processor.py",
        type: "command_injection",
        framework: "pytest"
      })

      assert %{
        "testFileName" => "test_command_injection_file_processor.py",
        "testPath" => "tests/security/test_command_injection_file_processor.py"
      } = json_response(conn, 200)
    end

    test "Path traversal in Express route", %{conn: conn, api_key: api_key} do
      conn = conn |> put_req_header("x-api-key", api_key.key)
      conn = post(conn, "/api/v1/test-integration/naming", %{
        vulnerableFile: "src/routes/fileDownload.js",
        type: "path_traversal",
        framework: "jest"
      })

      assert %{
        "testFileName" => "FileDownload.pathTraversal.test.js",
        "testPath" => "__tests__/security/FileDownload.pathTraversal.test.js"
      } = json_response(conn, 200)
    end
  end
end
