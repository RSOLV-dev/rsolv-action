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
  use OpenApiSpex.ControllerSpecs

  alias Rsolv.AST.TestIntegrator
  alias Rsolv.AST.TestScorer
  alias Rsolv.RateLimiter
  alias Rsolv.TestIntegration.Naming
  alias OpenApiSpex.Schema

  require Logger

  plug RsolvWeb.Plugs.ApiAuthentication

  action_fallback RsolvWeb.FallbackController

  @supported_frameworks ~w(vitest jest mocha rspec pytest minitest)
  @supported_languages ~w(javascript typescript ruby python)
  @analyze_supported_frameworks ~w(rspec vitest jest pytest mocha minitest)

  tags(["Test Integration"])

  # OpenAPI Schema Definitions
  defmodule Schemas do
    require OpenApiSpex

    defmodule RedTest do
      OpenApiSpex.schema(%{
        title: "RedTest",
        description: "A single RED test (fails on vulnerable code)",
        type: :object,
        required: [:testName, :testCode, :attackVector],
        properties: %{
          testName: %Schema{type: :string, description: "Name of the test"},
          testCode: %Schema{type: :string, description: "Test code"},
          attackVector: %Schema{type: :string, description: "Attack vector used"},
          expectedBehavior: %Schema{type: :string, description: "Expected behavior"},
          vulnerableCodePath: %Schema{type: :string, description: "Path to vulnerable code"},
          vulnerablePattern: %Schema{type: :string, description: "Vulnerable code pattern"}
        },
        example: %{
          "testName" => "rejects SQL injection in search endpoint",
          "testCode" =>
            "post('/search', { q: \"admin'; DROP TABLE users;--\" })\\nexpect(response.status).toBe(400)",
          "attackVector" => "admin'; DROP TABLE users;--",
          "expectedBehavior" => "should_fail_on_vulnerable_code"
        }
      })
    end

    defmodule TestSuite do
      OpenApiSpex.schema(%{
        title: "TestSuite",
        description: "Collection of RED tests",
        type: :object,
        required: [:redTests],
        properties: %{
          redTests: %Schema{
            type: :array,
            items: RedTest,
            description: "Array of RED tests"
          }
        },
        example: %{
          "redTests" => [
            %{
              "testName" => "rejects SQL injection",
              "testCode" => "...",
              "attackVector" => "'; DROP TABLE users;--"
            }
          ]
        }
      })
    end

    defmodule GenerateRequest do
      OpenApiSpex.schema(%{
        title: "GenerateRequest",
        description: "Request to generate integrated test file",
        type: :object,
        required: [:targetFileContent, :testSuite, :framework, :language],
        properties: %{
          targetFileContent: %Schema{type: :string, description: "Target test file content"},
          testSuite: TestSuite,
          framework: %Schema{type: :string, enum: ["vitest", "jest", "mocha"]},
          language: %Schema{type: :string, enum: ["javascript", "typescript"]},
          requestId: %Schema{type: :string, description: "Optional request ID"}
        }
      })
    end

    defmodule InsertionPoint do
      OpenApiSpex.schema(%{
        title: "InsertionPoint",
        description: "Where the test was inserted",
        type: :object,
        properties: %{
          line: %Schema{type: :integer, description: "Line number"},
          strategy: %Schema{type: :string, description: "Insertion strategy used"}
        }
      })
    end

    defmodule GenerateResponse do
      OpenApiSpex.schema(%{
        title: "GenerateResponse",
        description: "Integrated test file content",
        type: :object,
        required: [:requestId, :integratedContent, :method],
        properties: %{
          requestId: %Schema{type: :string},
          integratedContent: %Schema{
            type: :string,
            description: "Complete integrated file content"
          },
          method: %Schema{
            type: :string,
            enum: ["ast", "append"],
            description: "Integration method used"
          },
          insertionPoint: InsertionPoint,
          timing: %Schema{
            type: :object,
            properties: %{
              totalTimeMs: %Schema{type: :integer, description: "Total processing time"}
            }
          }
        }
      })
    end

    defmodule NamingRequest do
      OpenApiSpex.schema(%{
        title: "NamingRequest",
        description: "Request to generate semantic test file name",
        type: :object,
        required: [:vulnerableFile, :type, :framework],
        properties: %{
          vulnerableFile: %Schema{type: :string, description: "Path to vulnerable file"},
          type: %Schema{type: :string, description: "Vulnerability type (e.g., sql_injection)"},
          framework: %Schema{type: :string, description: "Test framework"}
        },
        example: %{
          "vulnerableFile" => "app/controllers/users_controller.rb",
          "type" => "sql_injection",
          "framework" => "rspec"
        }
      })
    end

    defmodule NamingResponse do
      OpenApiSpex.schema(%{
        title: "NamingResponse",
        description: "Generated test file name and path",
        type: :object,
        required: [:testFileName, :testPath],
        properties: %{
          testFileName: %Schema{type: :string, description: "Test file name"},
          testPath: %Schema{type: :string, description: "Full test file path"}
        },
        example: %{
          "testFileName" => "users_controller_sql_injection_spec.rb",
          "testPath" => "spec/security/users_controller_sql_injection_spec.rb"
        }
      })
    end

    defmodule AnalyzeRequest do
      OpenApiSpex.schema(%{
        title: "AnalyzeRequest",
        description: "Request to analyze and score test file candidates",
        type: :object,
        required: [:vulnerableFile, :candidateTestFiles, :framework],
        properties: %{
          vulnerableFile: %Schema{type: :string, description: "Path to vulnerable source file"},
          vulnerabilityType: %Schema{
            type: :string,
            description: "Type of vulnerability (optional)"
          },
          candidateTestFiles: %Schema{
            type: :array,
            items: %Schema{type: :string},
            description: "Array of candidate test file paths"
          },
          framework: %Schema{
            type: :string,
            enum: ["rspec", "vitest", "jest", "pytest", "mocha", "minitest"]
          }
        },
        example: %{
          "vulnerableFile" => "app/controllers/users_controller.rb",
          "vulnerabilityType" => "sql_injection",
          "candidateTestFiles" => [
            "spec/controllers/users_controller_spec.rb",
            "spec/requests/users_spec.rb"
          ],
          "framework" => "rspec"
        }
      })
    end

    defmodule Recommendation do
      OpenApiSpex.schema(%{
        title: "Recommendation",
        description: "Scored test file recommendation",
        type: :object,
        required: [:path, :score, :reason],
        properties: %{
          path: %Schema{type: :string, description: "Path to test file"},
          score: %Schema{type: :number, format: :float, description: "Score (0.0-1.5)"},
          reason: %Schema{type: :string, description: "Explanation of score"}
        }
      })
    end

    defmodule Fallback do
      OpenApiSpex.schema(%{
        title: "Fallback",
        description: "Fallback path suggestion",
        type: :object,
        required: [:path, :reason],
        properties: %{
          path: %Schema{type: :string, description: "Suggested new file path"},
          reason: %Schema{type: :string, description: "Why this path was suggested"}
        }
      })
    end

    defmodule AnalyzeResponse do
      OpenApiSpex.schema(%{
        title: "AnalyzeResponse",
        description: "Scored recommendations for test file integration",
        type: :object,
        required: [:recommendations, :fallback],
        properties: %{
          recommendations: %Schema{
            type: :array,
            items: Recommendation,
            description: "Sorted candidates (highest score first)"
          },
          fallback: Fallback
        },
        example: %{
          "recommendations" => [
            %{
              "path" => "spec/controllers/users_controller_spec.rb",
              "score" => 1.5,
              "reason" => "Direct unit test for vulnerable controller"
            },
            %{
              "path" => "spec/requests/users_spec.rb",
              "score" => 0.6,
              "reason" => "Request spec exercises controller"
            }
          ],
          "fallback" => %{
            "path" => "spec/security/users_controller_security_spec.rb",
            "reason" => "No existing test found"
          }
        }
      })
    end

    defmodule ErrorResponse do
      OpenApiSpex.schema(%{
        title: "ErrorResponse",
        description: "Error response",
        type: :object,
        required: [:error, :requestId],
        properties: %{
          error: %Schema{
            type: :object,
            properties: %{
              code: %Schema{type: :string},
              message: %Schema{type: :string}
            }
          },
          requestId: %Schema{type: :string},
          retryAfter: %Schema{
            type: :integer,
            description: "Retry after seconds (for rate limits)"
          }
        }
      })
    end
  end

  operation(:analyze,
    summary: "Score test file candidates for integration",
    description: """
    Analyzes candidate test files and returns scored recommendations for test integration.

    **Scoring Algorithm:**
    - Base score (0.0-1.0): Path similarity using Jaccard similarity
    - Module bonus (+0.3): Same module name (ignoring test suffixes)
    - Directory bonus (+0.2): Same directory structure
    - Total range: 0.0-1.5

    **Use Case:**
    Frontend scans filesystem for test files, sends candidates to this endpoint,
    receives scored recommendations, picks highest-scoring file for integration.

    **Requires:** Valid API key
    **Rate Limit:** 100 requests per minute per customer
    """,
    request_body: {
      "Test file analysis request",
      "application/json",
      Schemas.AnalyzeRequest,
      required: true
    },
    responses: [
      ok: {"Success", "application/json", Schemas.AnalyzeResponse},
      bad_request: {"Invalid request", "application/json", Schemas.ErrorResponse},
      unauthorized: {"Authentication failed", "application/json", Schemas.ErrorResponse},
      too_many_requests: {"Rate limit exceeded", "application/json", Schemas.ErrorResponse},
      internal_server_error: {"Server error", "application/json", Schemas.ErrorResponse}
    ]
  )

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

  ## Error Responses

  - 400: Invalid request (missing required fields, invalid framework)
  - 401: Authentication failed
  - 429: Rate limit exceeded
  - 500: Internal error
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

  operation(:generate,
    summary: "Generate integrated test file using AST",
    description: """
    Integrates security tests into existing test files using AST manipulation.

    **Process:**
    1. Parse target test file to AST
    2. Find appropriate insertion point
    3. Insert test suite
    4. Serialize back to code
    5. Fallback to simple append if AST fails

    **Supported Frameworks:**
    - JavaScript/TypeScript: Vitest, Jest, Mocha

    **Requires:** Valid API key with test integration permissions
    **Rate Limit:** 100 requests per minute per customer
    """,
    request_body: {
      "Test integration request",
      "application/json",
      Schemas.GenerateRequest,
      required: true
    },
    responses: [
      ok: {"Success", "application/json", Schemas.GenerateResponse},
      bad_request: {"Invalid request", "application/json", Schemas.ErrorResponse},
      unauthorized: {"Authentication failed", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Integration failed", "application/json", Schemas.ErrorResponse},
      too_many_requests: {"Rate limit exceeded", "application/json", Schemas.ErrorResponse},
      internal_server_error: {"Server error", "application/json", Schemas.ErrorResponse}
    ]
  )

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

    Logger.info(
      "TestIntegrationController: Received generate request from customer #{customer.id}"
    )

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

      Logger.info(
        "TestIntegrationController: Successfully generated integration (method: #{method}, time: #{total_time}ms)"
      )

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

  operation(:naming,
    summary: "Generate semantic test file name",
    description: """
    Generates semantic test file name based on vulnerability type and framework conventions.

    **Supported Frameworks:**
    - Ruby: RSpec, Minitest
    - JavaScript/TypeScript: Vitest, Jest, Mocha
    - Python: pytest, unittest

    **Naming Conventions:**
    - RSpec: `{module}_controller_{type}_spec.rb` → `spec/security/`
    - Vitest/Jest: `{Module}.{type}.test.ts` → `__tests__/security/`
    - pytest: `test_{type}_{module}.py` → `tests/security/`

    **Requires:** Valid API key
    **Rate Limit:** 100 requests per minute per customer
    """,
    request_body: {
      "Naming request",
      "application/json",
      Schemas.NamingRequest,
      required: true
    },
    responses: [
      ok: {"Success", "application/json", Schemas.NamingResponse},
      bad_request: {"Invalid request", "application/json", Schemas.ErrorResponse},
      unauthorized: {"Authentication failed", "application/json", Schemas.ErrorResponse}
    ]
  )

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
    with {:ok, validated_params} <- validate_naming_params(params) do
      result = generate_test_name(validated_params)
      json(conn, result)
    else
      {:error, :vulnerableFile_required} ->
        conn
        |> put_status(422)
        |> json(%{error: %{code: "VALIDATION_ERROR", message: "vulnerableFile is required"}})

      {:error, :type_required} ->
        conn
        |> put_status(422)
        |> json(%{error: %{code: "VALIDATION_ERROR", message: "type is required"}})

      {:error, :framework_required} ->
        conn
        |> put_status(422)
        |> json(%{error: %{code: "VALIDATION_ERROR", message: "framework is required"}})
    end
  end

  # Private functions

  defp handle_generate_error(conn, error, request_id) do
    case error do
      {:error, :rate_limited} ->
        send_error_response(
          conn,
          429,
          "RATE_LIMITED",
          "Rate limit exceeded. Please try again later.",
          request_id,
          %{retryAfter: 60}
        )

      {:error, {:validation, message}} ->
        send_error_response(conn, 400, "INVALID_REQUEST", message, request_id)

      {:error, {:unsupported_framework, framework}} ->
        send_error_response(
          conn,
          422,
          "UNSUPPORTED_FRAMEWORK",
          "Framework '#{framework}' is not supported. Supported: #{Enum.join(@supported_frameworks, ", ")}",
          request_id
        )

      {:error, reason} ->
        Logger.error("TestIntegrationController: Integration failed: #{inspect(reason)}")

        send_error_response(
          conn,
          500,
          "INTEGRATION_FAILED",
          "Failed to integrate test",
          request_id
        )
    end
  end

  defp send_error_response(conn, status, code, message, request_id, extra \\ %{}) do
    conn
    |> maybe_add_retry_after(status)
    |> put_status(status)
    |> json(
      Map.merge(
        %{
          error: %{code: code, message: message},
          requestId: request_id
        },
        extra
      )
    )
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
    with :ok <-
           validate_required_fields(params, ~w(targetFileContent testSuite framework language)),
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
      nil ->
        :ok

      test ->
        missing = required_test_fields -- Map.keys(test)
        {:error, {:validation, "Test missing required fields: #{Enum.join(missing, ", ")}"}}
    end
  end

  defp validate_naming_params(params) do
    with {:ok, vulnerable_file} <- extract_param(params, "vulnerableFile", :vulnerableFile),
         {:ok, type} <- extract_param(params, "type", :type),
         {:ok, framework} <- extract_param(params, "framework", :framework) do
      {:ok,
       %{
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
    do: "test-int-#{System.system_time(:millisecond)}-#{:rand.uniform(999_999)}"

  # Analyze endpoint validation helpers

  defp validate_analyze_request(params) do
    with :ok <-
           validate_required_fields_analyze(
             params,
             ~w(vulnerableFile candidateTestFiles framework)
           ),
         :ok <- validate_candidate_files(params["candidateTestFiles"]),
         :ok <- validate_analyze_framework(params["framework"]) do
      {:ok, params}
    end
  end

  defp validate_required_fields_analyze(params, required_fields) do
    missing = required_fields -- Map.keys(params)

    if Enum.empty?(missing),
      do: :ok,
      else: {:error, {:validation, "Missing required fields: #{Enum.join(missing, ", ")}"}}
  end

  defp validate_candidate_files(nil), do: {:error, {:validation, "candidateTestFiles required"}}

  defp validate_candidate_files([]),
    do: {:error, {:validation, "at least one candidate test file required"}}

  defp validate_candidate_files(files) when not is_list(files),
    do: {:error, {:validation, "candidateTestFiles must be an array"}}

  defp validate_candidate_files(files) when is_list(files) do
    if Enum.all?(files, &is_binary/1),
      do: :ok,
      else: {:error, {:validation, "candidateTestFiles must be an array of strings"}}
  end

  defp validate_analyze_framework(framework) when framework in @analyze_supported_frameworks,
    do: :ok

  defp validate_analyze_framework(nil), do: {:error, {:validation, "framework required"}}

  defp validate_analyze_framework(framework) when not is_binary(framework),
    do: {:error, {:validation, "framework must be a string"}}

  defp validate_analyze_framework(framework) when is_binary(framework) do
    supported_list = Enum.join(@analyze_supported_frameworks, ", ")
    {:error, {:validation, "unsupported framework: #{framework}. Supported: #{supported_list}"}}
  end
end
