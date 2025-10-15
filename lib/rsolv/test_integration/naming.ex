defmodule Rsolv.TestIntegration.Naming do
  @moduledoc """
  Generates semantic test file names based on vulnerability type and framework conventions.

  RFC-060-AMENDMENT-001: Helper API for naming validation tests.
  Created: 2025-10-13

  ## Naming Patterns by Framework

  ### RSpec (Ruby)
  ```ruby
  # Input: app/controllers/users_controller.rb, sql_injection
  # Output: spec/security/users_controller_sql_injection_spec.rb
  Pattern: {module}_{vulnerability_type}_spec.rb
  Location: spec/security/
  ```

  ### Jest/Vitest (JS/TS)
  ```javascript
  // Input: src/controllers/UsersController.ts, sql_injection
  // Output: __tests__/security/UsersController.sqlInjection.test.ts
  Pattern: {Module}.{vulnerabilityType}.test.{ext}
  Location: __tests__/security/ or test/security/
  ```

  ### pytest (Python)
  ```python
  # Input: app/controllers/users_controller.py, sql_injection
  # Output: tests/security/test_sql_injection_users_controller.py
  Pattern: test_{vulnerability_type}_{module}.py
  Location: tests/security/
  ```

  ## Examples

      iex> Rsolv.TestIntegration.Naming.generate_test_name(
      ...>   "app/users.rb",
      ...>   "sql_injection",
      ...>   "rspec"
      ...> )
      %{
        testFileName: "users_sql_injection_spec.rb",
        testPath: "spec/security/users_sql_injection_spec.rb"
      }

      iex> Rsolv.TestIntegration.Naming.generate_test_name(
      ...>   "src/controllers/UsersController.ts",
      ...>   "sql_injection",
      ...>   "vitest"
      ...> )
      %{
        testFileName: "UsersController.sqlInjection.test.ts",
        testPath: "__tests__/security/UsersController.sqlInjection.test.ts"
      }

      iex> Rsolv.TestIntegration.Naming.generate_test_name(
      ...>   "app/controllers/users_controller.py",
      ...>   "sql_injection",
      ...>   "pytest"
      ...> )
      %{
        testFileName: "test_sql_injection_users_controller.py",
        testPath: "tests/security/test_sql_injection_users_controller.py"
      }
  """

  @doc """
  Generates a semantic test file name and path based on vulnerability type and framework.

  ## Parameters
    - `vulnerable_file`: Path to the vulnerable file (e.g., "app/controllers/users_controller.rb")
    - `vulnerability_type`: Type of vulnerability (e.g., "sql_injection", "xss")
    - `framework`: Test framework (e.g., "rspec", "vitest", "jest", "pytest")

  ## Returns
    - `%{testFileName: String.t(), testPath: String.t()}`

  ## Examples

      iex> generate_test_name("app/models/user.rb", "mass_assignment", "rspec")
      %{
        testFileName: "user_mass_assignment_spec.rb",
        testPath: "spec/security/user_mass_assignment_spec.rb"
      }

      iex> generate_test_name("src/api/Auth.ts", "jwt_weak_secret", "jest")
      %{
        testFileName: "Auth.jwtWeakSecret.test.ts",
        testPath: "__tests__/security/Auth.jwtWeakSecret.test.ts"
      }
  """
  def generate_test_name(vulnerable_file, vulnerability_type, framework) do
    module_name = extract_module_name(vulnerable_file)
    file_extension = extract_extension(vulnerable_file)

    case framework do
      framework when framework in ["rspec", "minitest"] ->
        generate_ruby_test_name(module_name, vulnerability_type)

      framework when framework in ["jest", "vitest", "mocha"] ->
        generate_js_test_name(module_name, vulnerability_type, file_extension)

      framework when framework in ["pytest", "unittest"] ->
        generate_python_test_name(module_name, vulnerability_type)

      _ ->
        # Fallback: use generic pattern
        generate_generic_test_name(module_name, vulnerability_type, file_extension)
    end
  end

  # Ruby (RSpec/Minitest) naming: snake_case with _spec.rb suffix
  defp generate_ruby_test_name(module_name, vulnerability_type) do
    snake_module = to_snake_case(module_name)
    snake_vuln = to_snake_case(vulnerability_type)

    file_name = "#{snake_module}_#{snake_vuln}_spec.rb"
    test_path = "spec/security/#{file_name}"

    %{
      testFileName: file_name,
      testPath: test_path
    }
  end

  # JavaScript/TypeScript (Jest/Vitest/Mocha) naming: PascalCase.camelCase.test.ext
  defp generate_js_test_name(module_name, vulnerability_type, extension) do
    pascal_module = to_pascal_case(module_name)
    camel_vuln = to_camel_case(vulnerability_type)

    # Preserve original extension (.js, .ts, .jsx, .tsx)
    test_ext =
      case extension do
        ext when ext in [".ts", ".tsx", ".js", ".jsx"] -> ext
        # Default to .js if unknown
        _ -> ".js"
      end

    file_name = "#{pascal_module}.#{camel_vuln}.test#{test_ext}"
    test_path = "__tests__/security/#{file_name}"

    %{
      testFileName: file_name,
      testPath: test_path
    }
  end

  # Python (pytest/unittest) naming: test_snake_case.py prefix
  defp generate_python_test_name(module_name, vulnerability_type) do
    snake_module = to_snake_case(module_name)
    snake_vuln = to_snake_case(vulnerability_type)

    file_name = "test_#{snake_vuln}_#{snake_module}.py"
    test_path = "tests/security/#{file_name}"

    %{
      testFileName: file_name,
      testPath: test_path
    }
  end

  # Generic fallback naming
  defp generate_generic_test_name(module_name, vulnerability_type, extension) do
    snake_module = to_snake_case(module_name)
    snake_vuln = to_snake_case(vulnerability_type)

    file_name = "#{snake_module}_#{snake_vuln}_test#{extension}"
    test_path = "tests/security/#{file_name}"

    %{
      testFileName: file_name,
      testPath: test_path
    }
  end

  @doc """
  Extracts the module/class name from a file path.

  For files with multiple dots (e.g., file.parser.v2.js), only extracts
  the first part before any dots.

  ## Examples

      iex> extract_module_name("app/controllers/users_controller.rb")
      "users_controller"

      iex> extract_module_name("src/api/AuthService.ts")
      "AuthService"

      iex> extract_module_name("lib/utils/validator.py")
      "validator"

      iex> extract_module_name("src/utils/file.parser.v2.js")
      "file"
  """
  def extract_module_name(file_path) do
    file_path
    |> Path.basename()
    # Remove extension
    |> Path.rootname()
    |> String.split(".")
    # Take only the first part before any dots
    |> List.first()
  end

  @doc """
  Extracts the file extension from a file path.

  ## Examples

      iex> extract_extension("app/models/user.rb")
      ".rb"

      iex> extract_extension("src/controllers/Auth.ts")
      ".ts"

      iex> extract_extension("lib/utils.py")
      ".py"
  """
  def extract_extension(file_path) do
    Path.extname(file_path)
  end

  # Convert string to snake_case
  defp to_snake_case(string) do
    string
    # Insert _ before capitals
    |> String.replace(~r/([A-Z])/, "_\\1")
    |> String.downcase()
    # Remove leading underscore
    |> String.replace(~r/^_/, "")
    # Collapse multiple underscores
    |> String.replace(~r/__+/, "_")
    # Replace hyphens with underscores
    |> String.replace("-", "_")
  end

  # Convert string to PascalCase
  # Handles: snake_case, kebab-case, and already PascalCase/camelCase
  defp to_pascal_case(string) do
    # First, handle already camelCase or PascalCase by inserting underscores before capitals
    # e.g., "fileDownload" -> "file_Download", "FileDownload" -> "File_Download"
    with_underscores = String.replace(string, ~r/([a-z])([A-Z])/, "\\1_\\2")

    with_underscores
    # Split on _ and - only
    |> String.split(~r/[_\-]/)
    # Remove empty strings
    |> Enum.filter(&(&1 != ""))
    |> Enum.map(&String.capitalize/1)
    |> Enum.join("")
  end

  # Convert string to camelCase
  defp to_camel_case(string) do
    string
    |> to_pascal_case()
    |> then(fn str ->
      case String.split_at(str, 1) do
        {first, rest} -> String.downcase(first) <> rest
        _ -> str
      end
    end)
  end
end
