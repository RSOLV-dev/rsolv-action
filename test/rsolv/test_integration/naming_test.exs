defmodule Rsolv.TestIntegration.NamingTest do
  @moduledoc """
  Tests for semantic test file naming across different frameworks.

  RFC-060-AMENDMENT-001: Phase 1-Backend - Semantic naming helper API
  Created: 2025-10-13

  Tests cover:
  - RSpec (Ruby) naming conventions
  - Jest/Vitest/Mocha (JS/TS) naming conventions
  - pytest/unittest (Python) naming conventions
  - Edge cases and special characters
  """
  use ExUnit.Case, async: true

  alias Rsolv.TestIntegration.Naming

  describe "RSpec (Ruby) naming conventions" do
    test "generates snake_case with _spec.rb suffix" do
      result =
        Naming.generate_test_name(
          "app/controllers/users_controller.rb",
          "sql_injection",
          "rspec"
        )

      assert result.testFileName == "users_controller_sql_injection_spec.rb"
      assert result.testPath == "spec/security/users_controller_sql_injection_spec.rb"
    end

    test "handles PascalCase file names by converting to snake_case" do
      result =
        Naming.generate_test_name(
          "app/models/UserAccount.rb",
          "mass_assignment",
          "rspec"
        )

      assert result.testFileName == "user_account_mass_assignment_spec.rb"
      assert result.testPath == "spec/security/user_account_mass_assignment_spec.rb"
    end

    test "handles vulnerability types with multiple words" do
      result =
        Naming.generate_test_name(
          "app/services/payment.rb",
          "command_injection",
          "rspec"
        )

      assert result.testFileName == "payment_command_injection_spec.rb"
      assert result.testPath == "spec/security/payment_command_injection_spec.rb"
    end

    test "works with minitest framework (same naming as rspec)" do
      result =
        Naming.generate_test_name(
          "lib/auth.rb",
          "weak_password",
          "minitest"
        )

      assert result.testFileName == "auth_weak_password_spec.rb"
      assert result.testPath == "spec/security/auth_weak_password_spec.rb"
    end
  end

  describe "Jest/Vitest/Mocha (JS/TS) naming conventions" do
    test "generates PascalCase.camelCase.test.js for JavaScript" do
      result =
        Naming.generate_test_name(
          "src/controllers/users_controller.js",
          "sql_injection",
          "vitest"
        )

      assert result.testFileName == "UsersController.sqlInjection.test.js"
      assert result.testPath == "__tests__/security/UsersController.sqlInjection.test.js"
    end

    test "preserves TypeScript extension (.ts)" do
      result =
        Naming.generate_test_name(
          "src/api/AuthService.ts",
          "jwt_weak_secret",
          "jest"
        )

      assert result.testFileName == "AuthService.jwtWeakSecret.test.ts"
      assert result.testPath == "__tests__/security/AuthService.jwtWeakSecret.test.ts"
    end

    test "preserves JSX extension (.jsx)" do
      result =
        Naming.generate_test_name(
          "src/components/UserForm.jsx",
          "xss_vulnerability",
          "vitest"
        )

      assert result.testFileName == "UserForm.xssVulnerability.test.jsx"
      assert result.testPath == "__tests__/security/UserForm.xssVulnerability.test.jsx"
    end

    test "preserves TSX extension (.tsx)" do
      result =
        Naming.generate_test_name(
          "src/components/SearchBar.tsx",
          "nosql_injection",
          "jest"
        )

      assert result.testFileName == "SearchBar.nosqlInjection.test.tsx"
      assert result.testPath == "__tests__/security/SearchBar.nosqlInjection.test.tsx"
    end

    test "handles snake_case file names by converting to PascalCase" do
      result =
        Naming.generate_test_name(
          "src/utils/file_parser.js",
          "path_traversal",
          "mocha"
        )

      assert result.testFileName == "FileParser.pathTraversal.test.js"
      assert result.testPath == "__tests__/security/FileParser.pathTraversal.test.js"
    end

    test "handles hyphenated file names" do
      result =
        Naming.generate_test_name(
          "src/api/user-service.ts",
          "authentication-bypass",
          "vitest"
        )

      assert result.testFileName == "UserService.authenticationBypass.test.ts"
      assert result.testPath == "__tests__/security/UserService.authenticationBypass.test.ts"
    end
  end

  describe "pytest/unittest (Python) naming conventions" do
    test "generates test_snake_case.py prefix" do
      result =
        Naming.generate_test_name(
          "app/controllers/users_controller.py",
          "sql_injection",
          "pytest"
        )

      assert result.testFileName == "test_sql_injection_users_controller.py"
      assert result.testPath == "tests/security/test_sql_injection_users_controller.py"
    end

    test "handles PascalCase file names by converting to snake_case" do
      result =
        Naming.generate_test_name(
          "app/models/UserAccount.py",
          "mass_assignment",
          "pytest"
        )

      assert result.testFileName == "test_mass_assignment_user_account.py"
      assert result.testPath == "tests/security/test_mass_assignment_user_account.py"
    end

    test "works with unittest framework (same naming as pytest)" do
      result =
        Naming.generate_test_name(
          "lib/auth.py",
          "weak_password",
          "unittest"
        )

      assert result.testFileName == "test_weak_password_auth.py"
      assert result.testPath == "tests/security/test_weak_password_auth.py"
    end

    test "handles vulnerability types with multiple words" do
      result =
        Naming.generate_test_name(
          "app/services/payment.py",
          "command_injection",
          "pytest"
        )

      assert result.testFileName == "test_command_injection_payment.py"
      assert result.testPath == "tests/security/test_command_injection_payment.py"
    end
  end

  describe "edge cases and special characters" do
    test "handles files with multiple dots in name" do
      result =
        Naming.generate_test_name(
          "src/utils/file.parser.v2.js",
          "validation_bypass",
          "vitest"
        )

      # Takes only the first part before dots (cleaner naming)
      assert result.testFileName == "File.validationBypass.test.js"
      assert result.testPath == "__tests__/security/File.validationBypass.test.js"
    end

    test "handles very long file names gracefully" do
      result =
        Naming.generate_test_name(
          "app/services/super_long_authentication_and_authorization_service.rb",
          "privilege_escalation",
          "rspec"
        )

      assert result.testFileName ==
               "super_long_authentication_and_authorization_service_privilege_escalation_spec.rb"

      # Name is long but valid
      assert String.length(result.testFileName) > 50
    end

    test "handles single-letter file names" do
      result =
        Naming.generate_test_name(
          "lib/a.rb",
          "xss",
          "rspec"
        )

      assert result.testFileName == "a_xss_spec.rb"
      assert result.testPath == "spec/security/a_xss_spec.rb"
    end

    test "handles numbers in file names (Ruby)" do
      result =
        Naming.generate_test_name(
          "app/v2/api_controller.rb",
          "sql_injection",
          "rspec"
        )

      assert result.testFileName == "api_controller_sql_injection_spec.rb"
    end

    test "handles numbers in file names (JavaScript)" do
      result =
        Naming.generate_test_name(
          "src/v2/ApiController.ts",
          "sql_injection",
          "vitest"
        )

      assert result.testFileName == "ApiController.sqlInjection.test.ts"
    end

    test "handles unknown framework with generic fallback" do
      result =
        Naming.generate_test_name(
          "app/service.rb",
          "vulnerability",
          "unknown_framework"
        )

      # Fallback should use snake_case with _test suffix
      assert result.testFileName == "service_vulnerability_test.rb"
      assert result.testPath == "tests/security/service_vulnerability_test.rb"
    end
  end

  describe "extract_module_name/1" do
    test "extracts module name from path with extension" do
      assert Naming.extract_module_name("app/controllers/users_controller.rb") ==
               "users_controller"

      assert Naming.extract_module_name("src/api/AuthService.ts") == "AuthService"
      assert Naming.extract_module_name("lib/utils.py") == "utils"
    end

    test "handles files with multiple dots - takes only first part" do
      assert Naming.extract_module_name("src/file.parser.v2.js") == "file"
    end

    test "handles bare file name without path" do
      assert Naming.extract_module_name("service.rb") == "service"
    end
  end

  describe "extract_extension/1" do
    test "extracts file extension" do
      assert Naming.extract_extension("app/model.rb") == ".rb"
      assert Naming.extract_extension("src/controller.ts") == ".ts"
      assert Naming.extract_extension("lib/util.py") == ".py"
      assert Naming.extract_extension("src/component.jsx") == ".jsx"
    end

    test "returns empty string for files without extension" do
      assert Naming.extract_extension("README") == ""
    end

    test "handles multiple dots correctly (only last extension)" do
      assert Naming.extract_extension("file.test.js") == ".js"
    end
  end

  describe "real-world vulnerability examples" do
    test "SQL injection in Rails controller" do
      result =
        Naming.generate_test_name(
          "app/controllers/api/v1/users_controller.rb",
          "sql_injection",
          "rspec"
        )

      assert result.testFileName == "users_controller_sql_injection_spec.rb"
      assert result.testPath == "spec/security/users_controller_sql_injection_spec.rb"
    end

    test "XSS in React component" do
      result =
        Naming.generate_test_name(
          "src/components/UserProfile.tsx",
          "xss_reflected",
          "vitest"
        )

      assert result.testFileName == "UserProfile.xssReflected.test.tsx"
      assert result.testPath == "__tests__/security/UserProfile.xssReflected.test.tsx"
    end

    test "Command injection in Python service" do
      result =
        Naming.generate_test_name(
          "app/services/file_processor.py",
          "command_injection",
          "pytest"
        )

      assert result.testFileName == "test_command_injection_file_processor.py"
      assert result.testPath == "tests/security/test_command_injection_file_processor.py"
    end

    test "Path traversal in Node.js Express route" do
      result =
        Naming.generate_test_name(
          "src/routes/fileDownload.js",
          "path_traversal",
          "jest"
        )

      assert result.testFileName == "FileDownload.pathTraversal.test.js"
      assert result.testPath == "__tests__/security/FileDownload.pathTraversal.test.js"
    end

    test "NoSQL injection in MongoDB service" do
      result =
        Naming.generate_test_name(
          "lib/database/user_repository.rb",
          "nosql_injection",
          "rspec"
        )

      assert result.testFileName == "user_repository_nosql_injection_spec.rb"
      assert result.testPath == "spec/security/user_repository_nosql_injection_spec.rb"
    end
  end
end
