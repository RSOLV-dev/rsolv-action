defmodule RsolvWeb.Api.V1.FrameworkController do
  use RsolvWeb, :controller
  use OpenApiSpex.ControllerSpecs

  require Logger

  alias Rsolv.Frameworks.Detector
  alias OpenApiSpex.Schema

  # OpenAPI Schema Definitions
  defmodule Schemas do
    require OpenApiSpex

    defmodule PackageJson do
      OpenApiSpex.schema(%{
        title: "PackageJson",
        description: "JavaScript/TypeScript package.json content",
        type: :object,
        properties: %{
          devDependencies: %Schema{
            type: :object,
            description: "Development dependencies",
            additionalProperties: %Schema{type: :string}
          }
        },
        example: %{
          "devDependencies" => %{
            "vitest" => "^1.0.0",
            "typescript" => "^5.0.0"
          }
        }
      })
    end

    defmodule DetectRequest do
      OpenApiSpex.schema(%{
        title: "FrameworkDetectRequest",
        description: "Request body for framework detection",
        type: :object,
        properties: %{
          packageJson: %Schema{
            anyOf: [
              PackageJson,
              %Schema{type: :null}
            ],
            description: "Parsed package.json content (JavaScript/TypeScript)",
            nullable: true
          },
          gemfile: %Schema{
            type: :string,
            nullable: true,
            description: "Gemfile content as string (Ruby)"
          },
          requirementsTxt: %Schema{
            type: :string,
            nullable: true,
            description: "requirements.txt content as string (Python)"
          },
          configFiles: %Schema{
            type: :array,
            items: %Schema{type: :string},
            description: "List of config file names found in the repository",
            example: ["vitest.config.ts", "jest.config.js"]
          }
        },
        example: %{
          "packageJson" => %{
            "devDependencies" => %{"vitest" => "^1.0.0"}
          },
          "gemfile" => nil,
          "requirementsTxt" => nil,
          "configFiles" => ["vitest.config.ts"]
        }
      })
    end

    defmodule DetectResponse do
      OpenApiSpex.schema(%{
        title: "FrameworkDetectResponse",
        description: "Framework detection result",
        type: :object,
        required: [:framework, :testDir],
        properties: %{
          framework: %Schema{
            type: :string,
            description: "Primary test framework detected",
            example: "vitest"
          },
          version: %Schema{
            type: :string,
            nullable: true,
            description: "Framework version if available",
            example: "1.0.0"
          },
          testDir: %Schema{
            type: :string,
            description: "Default test directory for this framework",
            example: "test/"
          },
          compatibleWith: %Schema{
            type: :array,
            items: %Schema{type: :string},
            description: "Other compatible frameworks detected",
            example: ["jest"]
          }
        }
      })
    end

    defmodule ErrorResponse do
      OpenApiSpex.schema(%{
        title: "ErrorResponse",
        description: "Error response",
        type: :object,
        required: [:error],
        properties: %{
          error: %Schema{
            type: :string,
            description: "Error message",
            example: "No test framework detected"
          },
          details: %Schema{
            type: :string,
            description: "Additional error details"
          }
        }
      })
    end
  end

  tags(["Framework Detection"])

  @moduledoc """
  API endpoint for test framework detection.

  ## Supported Frameworks

  - **JavaScript/TypeScript**: Vitest (priority 1), Jest, Mocha
  - **Ruby**: RSpec, Minitest
  - **Python**: pytest, unittest

  ## Detection Strategy

  1. Check package.json devDependencies (JS/TS)
  2. Check config files (vitest.config.ts, jest.config.js, etc.)
  3. Check Gemfile (Ruby)
  4. Check requirements.txt (Python)

  When multiple frameworks are detected, returns the highest priority framework
  as primary with others listed in `compatibleWith`.

  ## Access

  - No authentication required (public endpoint)
  - Rate limited: 100 requests per minute per IP (standard API rate limit)
  """

  operation(:detect,
    summary: "Detect test framework from package files",
    description: """
    Detects test framework from package file contents and configuration files.

    **Supported Frameworks:**
    - JavaScript/TypeScript: Vitest (priority 1), Jest, Mocha
    - Ruby: RSpec, Minitest
    - Python: pytest, unittest

    When multiple frameworks are detected, returns the highest priority framework
    as primary with others in `compatibleWith`.

    **Detection Sources:**
    1. package.json devDependencies (JS/TS)
    2. Config files (vitest.config.ts, jest.config.js, etc.)
    3. Gemfile (Ruby)
    4. requirements.txt (Python)

    **Access:** No authentication required (public endpoint)
    """,
    request_body: {
      "Framework detection request",
      "application/json",
      Schemas.DetectRequest,
      required: true
    },
    responses: [
      ok: {"Success", "application/json", Schemas.DetectResponse},
      bad_request: {"Invalid request", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Detection failed", "application/json", Schemas.ErrorResponse},
      internal_server_error: {"Server error", "application/json", Schemas.ErrorResponse}
    ]
  )

  @doc """
  POST /api/v1/framework/detect

  Detects test framework from package files.

  ## Request Body

  ```json
  {
    "packageJson": {
      "devDependencies": {
        "vitest": "^1.0.0"
      }
    },
    "gemfile": null,
    "requirementsTxt": null,
    "configFiles": ["vitest.config.ts"]
  }
  ```

  ## Success Response (200 OK)

  ```json
  {
    "framework": "vitest",
    "version": "1.0.0",
    "testDir": "test/",
    "compatibleWith": []
  }
  ```

  ## Error Responses

  ### 400 Bad Request - No input provided
  ```json
  {
    "error": "At least one package file must be provided",
    "details": "Provide packageJson, gemfile, requirementsTxt, or configFiles"
  }
  ```

  ### 422 Unprocessable Entity - No framework detected
  ```json
  {
    "error": "No test framework detected",
    "details": "Could not detect test framework from provided files"
  }
  ```

  ### 500 Internal Server Error
  ```json
  {
    "error": "Internal server error",
    "details": "An error occurred during framework detection"
  }
  ```
  """
  def detect(conn, params) do
    Logger.info("Framework detection API called")
    Logger.debug("Parameters: #{inspect(params)}")

    try do
      # Convert camelCase to snake_case for internal processing
      package_files = %{
        package_json: params["packageJson"],
        gemfile: params["gemfile"],
        requirements_txt: params["requirementsTxt"],
        config_files: params["configFiles"] || []
      }

      # Validate at least one input is provided
      if all_inputs_nil?(package_files) do
        Logger.warning("No package files provided")

        conn
        |> put_status(:bad_request)
        |> json(%{
          error: "At least one package file must be provided",
          details: "Provide packageJson, gemfile, requirementsTxt, or configFiles"
        })
      else
        case Detector.detect(package_files) do
          {:ok, result} ->
            Logger.info("Successfully detected framework: #{result.framework}")

            # Convert snake_case to camelCase for API response
            response = %{
              framework: result.framework,
              version: result.version,
              testDir: result.test_dir,
              compatibleWith: result.compatible_with
            }

            json(conn, response)

          {:error, reason} ->
            Logger.warning("Framework detection failed: #{reason}")

            conn
            |> put_status(:unprocessable_entity)
            |> json(%{
              error: reason,
              details: "Could not detect test framework from provided files"
            })
        end
      end
    rescue
      e ->
        Logger.error("Framework detection error: #{inspect(e)}")
        Logger.error(Exception.format_stacktrace())

        conn
        |> put_status(:internal_server_error)
        |> json(%{
          error: "Internal server error",
          details: "An error occurred during framework detection"
        })
    end
  end

  # Check if all inputs are nil or empty
  defp all_inputs_nil?(package_files) do
    is_nil(package_files.package_json) &&
      is_nil_or_empty?(package_files.gemfile) &&
      is_nil_or_empty?(package_files.requirements_txt) &&
      (is_nil(package_files.config_files) || package_files.config_files == [])
  end

  defp is_nil_or_empty?(nil), do: true
  defp is_nil_or_empty?(""), do: true
  defp is_nil_or_empty?(_), do: false
end
