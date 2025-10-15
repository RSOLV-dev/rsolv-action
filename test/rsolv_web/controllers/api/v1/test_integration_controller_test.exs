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
      conn =
        post(conn, "/api/v1/test-integration/naming", %{
          vulnerableFile: "app/model.rb",
          type: "sql_injection",
          framework: "rspec"
        })

      assert json_response(conn, 401)
    end

    test "generates RSpec test name for Ruby file", %{conn: conn, api_key: api_key} do
      conn =
        conn
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
      conn =
        conn
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
      conn =
        conn
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
      conn =
        conn
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

      conn =
        post(conn, "/api/v1/test-integration/naming", %{
          vulnerableFile: "app/model.rb",
          type: "sql_injection",
          # Uppercase
          framework: "RSPEC"
        })

      assert %{
               "testFileName" => "model_sql_injection_spec.rb",
               "testPath" => "spec/security/model_sql_injection_spec.rb"
             } = json_response(conn, 200)
    end

    test "returns error when vulnerableFile is missing", %{conn: conn, api_key: api_key} do
      conn = conn |> put_req_header("x-api-key", api_key.key)

      conn =
        post(conn, "/api/v1/test-integration/naming", %{
          type: "sql_injection",
          framework: "rspec"
        })

      assert %{"error" => _} = json_response(conn, 422)
    end

    test "returns error when type is missing", %{conn: conn, api_key: api_key} do
      conn = conn |> put_req_header("x-api-key", api_key.key)

      conn =
        post(conn, "/api/v1/test-integration/naming", %{
          vulnerableFile: "app/model.rb",
          framework: "rspec"
        })

      assert %{"error" => _} = json_response(conn, 422)
    end

    test "returns error when framework is missing", %{conn: conn, api_key: api_key} do
      conn = conn |> put_req_header("x-api-key", api_key.key)

      conn =
        post(conn, "/api/v1/test-integration/naming", %{
          vulnerableFile: "app/model.rb",
          type: "sql_injection"
        })

      assert %{"error" => _} = json_response(conn, 422)
    end

    test "returns error when vulnerableFile is empty string", %{conn: conn, api_key: api_key} do
      conn = conn |> put_req_header("x-api-key", api_key.key)

      conn =
        post(conn, "/api/v1/test-integration/naming", %{
          vulnerableFile: "",
          type: "sql_injection",
          framework: "rspec"
        })

      assert %{"error" => _} = json_response(conn, 422)
    end

    test "handles complex file paths", %{conn: conn, api_key: api_key} do
      conn = conn |> put_req_header("x-api-key", api_key.key)

      conn =
        post(conn, "/api/v1/test-integration/naming", %{
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

      conn =
        post(conn, "/api/v1/test-integration/naming", %{
          vulnerableFile: "src/api/Auth.ts",
          # Hyphenated
          type: "jwt-weak-secret",
          framework: "jest"
        })

      response = json_response(conn, 200)
      assert response["testFileName"] =~ "jwtWeakSecret"
    end

    test "works with mocha framework", %{conn: conn, api_key: api_key} do
      conn = conn |> put_req_header("x-api-key", api_key.key)

      conn =
        post(conn, "/api/v1/test-integration/naming", %{
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

      conn =
        post(conn, "/api/v1/test-integration/naming", %{
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

      conn =
        post(conn, "/api/v1/test-integration/naming", %{
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

      conn =
        post(conn, "/api/v1/test-integration/naming", %{
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

      conn =
        post(conn, "/api/v1/test-integration/naming", %{
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

      conn =
        post(conn, "/api/v1/test-integration/naming", %{
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

      conn =
        post(conn, "/api/v1/test-integration/naming", %{
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

  describe "POST /api/v1/test-integration/analyze" do
    test "requires authentication", %{conn: conn} do
      conn =
        post(conn, "/api/v1/test-integration/analyze", %{
          vulnerableFile: "app/model.rb",
          candidateTestFiles: ["spec/model_spec.rb"],
          framework: "rspec"
        })

      assert json_response(conn, 401)
    end

    test "recommends best test file for integration based on semantic similarity", %{
      conn: conn,
      api_key: api_key
    } do
      # RFC-060-AMENDMENT-001: Backend scores test files to find best integration point
      # Scoring: 0.0-1.5 range (path similarity + module bonus +0.3 + directory bonus +0.2)
      conn =
        conn
        |> put_req_header("x-api-key", api_key.key)
        |> post("/api/v1/test-integration/analyze", %{
          vulnerableFile: "app/controllers/users_controller.rb",
          vulnerabilityType: "sql_injection",
          candidateTestFiles: [
            # Direct unit test - should score HIGHEST
            "spec/controllers/users_controller_spec.rb",
            # Integration test - should score MEDIUM
            "spec/requests/users_spec.rb",
            # Different component - should score LOWEST
            "spec/models/user_spec.rb"
          ],
          framework: "rspec"
        })

      response = json_response(conn, 200)
      assert %{"recommendations" => recommendations, "fallback" => fallback} = response

      # Desired behavior: Direct unit test scores highest
      [best | rest] = recommendations
      assert best["path"] == "spec/controllers/users_controller_spec.rb"
      assert best["score"] >= 1.0, "Direct unit test should score >= 1.0 (has module bonus)"
      assert best["score"] <= 1.5, "Score must be within RFC-specified range (0.0-1.5)"

      assert best["reason"] =~ ~r/(direct|unit|controller)/i,
             "Reason should explain why this is best choice"

      # Desired behavior: Scores are in descending order (best first)
      scores = Enum.map(recommendations, & &1["score"])

      assert scores == Enum.sort(scores, :desc),
             "Recommendations must be sorted by score descending"

      # Desired behavior: All scores are in valid range
      assert Enum.all?(scores, &(&1 >= 0.0 and &1 <= 1.5)), "All scores must be in range 0.0-1.5"

      # Desired behavior: Direct unit test significantly outranks unrelated tests
      model_spec = Enum.find(recommendations, &(&1["path"] =~ ~r/models/))
      score_gap = best["score"] - model_spec["score"]

      assert score_gap >= 0.3,
             "Direct unit test should score at least +0.3 higher than unrelated test (module bonus)"

      # Desired behavior: Fallback provides new file path when no good match exists
      assert fallback["path"] =~ ~r/spec\/security/,
             "Fallback should suggest security-specific test file"

      assert fallback["reason"], "Fallback must explain why it's needed"
    end

    test "prioritizes unit tests over integration tests for JavaScript/TypeScript", %{
      conn: conn,
      api_key: api_key
    } do
      # RFC-060-AMENDMENT-001: Path similarity scoring should prefer direct unit tests
      conn =
        conn
        |> put_req_header("x-api-key", api_key.key)
        |> post("/api/v1/test-integration/analyze", %{
          vulnerableFile: "src/controllers/AuthController.ts",
          vulnerabilityType: "jwt_weak_secret",
          candidateTestFiles: [
            # Direct unit test - closer path match
            "test/controllers/AuthController.test.ts",
            # Integration test - different directory
            "test/integration/auth.test.ts"
          ],
          framework: "jest"
        })

      response = json_response(conn, 200)
      assert %{"recommendations" => [best, second]} = response

      # Desired behavior: Unit test outranks integration test
      assert best["path"] == "test/controllers/AuthController.test.ts"

      assert best["score"] > second["score"],
             "Unit test should score higher than integration test"

      # Desired behavior: Score difference reflects semantic difference
      score_gap = best["score"] - second["score"]
      assert score_gap >= 0.2, "Score gap should reflect directory structure bonus (+0.2)"
    end

    test "returns error when vulnerableFile is missing", %{conn: conn, api_key: api_key} do
      conn =
        conn
        |> put_req_header("x-api-key", api_key.key)
        |> post("/api/v1/test-integration/analyze", %{
          candidateTestFiles: ["spec/model_spec.rb"],
          framework: "rspec"
        })

      response = json_response(conn, 400)
      assert %{"error" => %{"code" => "INVALID_REQUEST"}} = response
    end

    test "returns error when candidateTestFiles is empty", %{conn: conn, api_key: api_key} do
      conn =
        conn
        |> put_req_header("x-api-key", api_key.key)
        |> post("/api/v1/test-integration/analyze", %{
          vulnerableFile: "app/model.rb",
          candidateTestFiles: [],
          framework: "rspec"
        })

      response = json_response(conn, 400)
      assert %{"error" => %{"code" => "INVALID_REQUEST"}} = response
    end

    test "returns error when framework is unsupported", %{conn: conn, api_key: api_key} do
      conn =
        conn
        |> put_req_header("x-api-key", api_key.key)
        |> post("/api/v1/test-integration/analyze", %{
          vulnerableFile: "app/model.rb",
          candidateTestFiles: ["spec/model_spec.rb"],
          framework: "unsupported_framework"
        })

      response = json_response(conn, 400)
      assert %{"error" => %{"code" => "INVALID_REQUEST"}} = response
      assert response["error"]["message"] =~ "unsupported framework"
    end

    test "handles pytest framework", %{conn: conn, api_key: api_key} do
      conn =
        conn
        |> put_req_header("x-api-key", api_key.key)
        |> post("/api/v1/test-integration/analyze", %{
          vulnerableFile: "app/services/payment.py",
          candidateTestFiles: [
            "tests/services/test_payment.py",
            "tests/integration/test_payment_flow.py"
          ],
          framework: "pytest"
        })

      response = json_response(conn, 200)
      assert %{"recommendations" => recommendations} = response
      assert length(recommendations) == 2
    end
  end

  describe "POST /api/v1/test-integration/generate" do
    test "requires authentication", %{conn: conn} do
      conn =
        post(conn, "/api/v1/test-integration/generate", %{
          targetFileContent: "describe('test', () => {})",
          testSuite: %{redTests: []},
          framework: "vitest",
          language: "javascript"
        })

      assert json_response(conn, 401)
    end

    test "integrates security test into existing test file while preserving structure", %{
      conn: conn,
      api_key: api_key
    } do
      # RFC-060-AMENDMENT-001: AST integration should insert test at appropriate point
      # without breaking existing tests (lines 236-243)
      target_content = """
      describe('UsersController', () => {
        it('should create user', () => {
          expect(true).toBe(true);
        });
      });
      """

      test_suite = %{
        redTests: [
          %{
            testName: "rejects SQL injection in search",
            testCode: "expect(response.status).toBe(400)",
            attackVector: "admin'; DROP TABLE users;--",
            expectedBehavior: "should_fail_on_vulnerable_code",
            vulnerableCodePath: "src/controllers/UsersController.js:42",
            vulnerablePattern: "User.where(`name LIKE '%${q}%'`)"
          }
        ]
      }

      conn =
        conn
        |> put_req_header("x-api-key", api_key.key)
        |> post("/api/v1/test-integration/generate", %{
          targetFileContent: target_content,
          testSuite: test_suite,
          framework: "vitest",
          language: "javascript"
        })

      response = json_response(conn, 200)

      %{
        "integratedContent" => integrated,
        "method" => method,
        "insertionPoint" => insertion_point
      } = response

      # Desired behavior: Original test is preserved
      assert integrated =~ "should create user", "Original test must be preserved"

      # Desired behavior: New security test is added
      assert integrated =~ "rejects SQL injection in search", "New test must be integrated"
      assert integrated =~ "admin'; DROP TABLE users;--", "Attack vector must be included"

      # Desired behavior: Integration method is documented
      assert method in ["ast", "append"], "Method must indicate AST or fallback"

      # Desired behavior: Insertion point is provided (for AST method)
      if method == "ast" do
        assert insertion_point["strategy"], "AST integration must document strategy"
      end

      # Desired behavior: Integrated code maintains valid JavaScript syntax
      assert integrated =~ ~r/describe\s*\(/, "Must contain describe block"
      assert integrated =~ ~r/it\s*\(/, "Must contain it block"

      # Desired behavior: Tests are properly nested (may have security-specific describe block)
      it_count = Regex.scan(~r/it\s*\(/, integrated) |> length()
      assert it_count >= 2, "Should have at least 2 tests (original + new security test)"
    end

    test "gracefully falls back to append when AST parsing fails", %{conn: conn, api_key: api_key} do
      # RFC-060-AMENDMENT-001 lines 266-272: Fallback to simple append if AST fails
      # This tests the desired behavior: system remains functional even with unparseable code
      unparseable_content = """
      // Intentionally malformed JavaScript to trigger AST failure
      describe('Broken', () => {
        it('has syntax error', () => {
          expect(foo).toBe(bar)  // Missing semicolon
        }  // Missing closing brace
      """

      test_suite = %{
        redTests: [
          %{
            testName: "still adds security test despite AST failure",
            testCode: "expect(response.status).toBe(400);",
            attackVector: "test"
          }
        ]
      }

      conn =
        conn
        |> put_req_header("x-api-key", api_key.key)
        |> post("/api/v1/test-integration/generate", %{
          targetFileContent: unparseable_content,
          testSuite: test_suite,
          framework: "jest",
          language: "javascript"
        })

      response = json_response(conn, 200)

      %{
        "integratedContent" => integrated,
        "method" => method
      } = response

      # Desired behavior: Fallback succeeds even when AST fails
      assert method == "append", "Should use append fallback when AST parsing fails"

      # Desired behavior: Original content is preserved
      assert integrated =~ "Broken", "Original (even broken) content must be preserved"

      # Desired behavior: New test is still added
      assert integrated =~ "still adds security test despite AST failure"

      # Desired behavior: Test is appended (not inserted mid-file)
      original_size = String.length(unparseable_content)
      assert String.length(integrated) > original_size, "Content should be appended"
    end

    test "returns error when targetFileContent is missing", %{conn: conn, api_key: api_key} do
      conn =
        conn
        |> put_req_header("x-api-key", api_key.key)
        |> post("/api/v1/test-integration/generate", %{
          testSuite: %{redTests: []},
          framework: "vitest",
          language: "javascript"
        })

      response = json_response(conn, 400)
      assert %{"error" => %{"code" => "INVALID_REQUEST"}} = response
      assert response["error"]["message"] =~ "Missing required fields"
    end

    test "returns error when testSuite is missing redTests", %{conn: conn, api_key: api_key} do
      conn =
        conn
        |> put_req_header("x-api-key", api_key.key)
        |> post("/api/v1/test-integration/generate", %{
          targetFileContent: "describe('test', () => {})",
          testSuite: %{},
          framework: "vitest",
          language: "javascript"
        })

      response = json_response(conn, 400)
      assert %{"error" => %{"code" => "INVALID_REQUEST"}} = response
    end

    test "returns error when redTests array is empty", %{conn: conn, api_key: api_key} do
      conn =
        conn
        |> put_req_header("x-api-key", api_key.key)
        |> post("/api/v1/test-integration/generate", %{
          targetFileContent: "describe('test', () => {})",
          testSuite: %{redTests: []},
          framework: "vitest",
          language: "javascript"
        })

      response = json_response(conn, 400)
      assert %{"error" => %{"code" => "INVALID_REQUEST"}} = response
      assert response["error"]["message"] =~ "must not be empty"
    end

    test "returns error when framework is unsupported", %{conn: conn, api_key: api_key} do
      test_suite = %{
        redTests: [
          %{
            testName: "test",
            testCode: "expect(true).toBe(true)",
            attackVector: "test"
          }
        ]
      }

      conn =
        conn
        |> put_req_header("x-api-key", api_key.key)
        |> post("/api/v1/test-integration/generate", %{
          targetFileContent: "describe('test', () => {})",
          testSuite: test_suite,
          framework: "unsupported",
          language: "javascript"
        })

      response = json_response(conn, 400)
      assert %{"error" => %{"code" => "INVALID_REQUEST"}} = response
      assert response["error"]["message"] =~ "framework must be one of"
    end

    test "returns error when test is missing required fields", %{conn: conn, api_key: api_key} do
      test_suite = %{
        redTests: [
          %{
            testName: "incomplete test"
            # Missing testCode and attackVector
          }
        ]
      }

      conn =
        conn
        |> put_req_header("x-api-key", api_key.key)
        |> post("/api/v1/test-integration/generate", %{
          targetFileContent: "describe('test', () => {})",
          testSuite: test_suite,
          framework: "vitest",
          language: "javascript"
        })

      response = json_response(conn, 400)
      assert %{"error" => %{"code" => "INVALID_REQUEST"}} = response
      assert response["error"]["message"] =~ "missing required fields"
    end

    test "includes timing information in response", %{conn: conn, api_key: api_key} do
      test_suite = %{
        redTests: [
          %{
            testName: "test",
            testCode: "expect(true).toBe(true)",
            attackVector: "test"
          }
        ]
      }

      conn =
        conn
        |> put_req_header("x-api-key", api_key.key)
        |> post("/api/v1/test-integration/generate", %{
          targetFileContent: "describe('test', () => {})",
          testSuite: test_suite,
          framework: "vitest",
          language: "javascript"
        })

      response = json_response(conn, 200)
      assert %{"timing" => %{"totalTimeMs" => time_ms}} = response
      assert is_integer(time_ms)
      assert time_ms >= 0
    end

    test "accepts custom requestId", %{conn: conn, api_key: api_key} do
      custom_id = "custom-request-123"

      test_suite = %{
        redTests: [
          %{
            testName: "test",
            testCode: "expect(true).toBe(true)",
            attackVector: "test"
          }
        ]
      }

      conn =
        conn
        |> put_req_header("x-api-key", api_key.key)
        |> post("/api/v1/test-integration/generate", %{
          targetFileContent: "describe('test', () => {})",
          testSuite: test_suite,
          framework: "vitest",
          language: "javascript",
          requestId: custom_id
        })

      response = json_response(conn, 200)
      assert %{"requestId" => ^custom_id} = response
    end
  end
end
