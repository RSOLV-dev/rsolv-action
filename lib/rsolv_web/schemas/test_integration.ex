defmodule RsolvWeb.Schemas.TestIntegration do
  @moduledoc """
  OpenAPI schemas for test integration endpoints (AST-based test generation).
  """

  alias OpenApiSpex.Schema

  defmodule TestAnalyzeRequest do
    @moduledoc "Test code analysis request"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "TestAnalyzeRequest",
      description: "Request to analyze test code structure using AST",
      type: :object,
      properties: %{
        code: %Schema{
          type: :string,
          description: "Test code to analyze"
        },
        language: %Schema{
          type: :string,
          description: "Programming language",
          enum: ["javascript", "typescript", "python", "ruby"],
          example: "javascript"
        },
        framework: %Schema{
          type: :string,
          description: "Test framework (optional)",
          example: "jest"
        }
      },
      required: [:code, :language],
      example: %{
        "code" => "describe('User authentication', () => { it('should login', () => {}); });",
        "language" => "javascript",
        "framework" => "jest"
      }
    })
  end

  defmodule TestAnalyzeResponse do
    @moduledoc "Test code analysis response"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "TestAnalyzeResponse",
      description: "Analysis results for test code structure",
      type: :object,
      properties: %{
        structure: %Schema{
          type: :object,
          properties: %{
            suites: %Schema{type: :array, items: %Schema{type: :object}},
            tests: %Schema{type: :array, items: %Schema{type: :object}},
            hooks: %Schema{type: :array, items: %Schema{type: :object}}
          }
        },
        framework_detected: %Schema{type: :string},
        suggestions: %Schema{
          type: :array,
          items: %Schema{type: :string}
        }
      }
    })
  end

  defmodule TestNamingRequest do
    @moduledoc "Test naming suggestion request"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "TestNamingRequest",
      description: "Request test name suggestions based on code being tested",
      type: :object,
      properties: %{
        code: %Schema{
          type: :string,
          description: "Code being tested"
        },
        language: %Schema{
          type: :string,
          description: "Programming language",
          example: "javascript"
        },
        test_type: %Schema{
          type: :string,
          description: "Type of test",
          enum: ["unit", "integration", "e2e", "security"],
          example: "security"
        },
        context: %Schema{
          type: :object,
          description: "Additional context",
          properties: %{
            vulnerability_type: %Schema{type: :string},
            function_name: %Schema{type: :string}
          }
        }
      },
      required: [:code, :language, :test_type],
      example: %{
        "code" => "function sanitizeInput(input) { return input.replace(/<script>/g, ''); }",
        "language" => "javascript",
        "test_type" => "security",
        "context" => %{
          "vulnerability_type" => "xss",
          "function_name" => "sanitizeInput"
        }
      }
    })
  end

  defmodule TestNamingResponse do
    @moduledoc "Test naming suggestion response"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "TestNamingResponse",
      description: "Suggested test names and descriptions",
      type: :object,
      properties: %{
        suggestions: %Schema{
          type: :array,
          items: %Schema{
            type: :object,
            properties: %{
              test_name: %Schema{type: :string},
              description: %Schema{type: :string},
              category: %Schema{type: :string}
            }
          },
          description: "Array of test name suggestions"
        }
      },
      required: [:suggestions],
      example: %{
        "suggestions" => [
          %{
            "test_name" => "should block XSS via script tag injection",
            "description" => "Verifies that sanitizeInput prevents XSS through script tags",
            "category" => "security"
          },
          %{
            "test_name" => "should remove malicious script content",
            "description" => "Tests removal of script tags from user input",
            "category" => "sanitization"
          }
        ]
      }
    })
  end

  defmodule TestGenerateRequest do
    @moduledoc "Test generation request"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "TestGenerateRequest",
      description: "Request to generate test code using AST templates",
      type: :object,
      properties: %{
        code: %Schema{type: :string, description: "Code to test"},
        language: %Schema{type: :string, description: "Programming language"},
        test_type: %Schema{type: :string, enum: ["red", "green", "refactor"]},
        vulnerability_type: %Schema{type: :string, nullable: true},
        framework: %Schema{type: :string, description: "Test framework", nullable: true}
      },
      required: [:code, :language, :test_type]
    })
  end

  defmodule TestGenerateResponse do
    @moduledoc "Test generation response"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "TestGenerateResponse",
      description: "Generated test code",
      type: :object,
      properties: %{
        test_code: %Schema{type: :string, description: "Generated test code"},
        test_name: %Schema{type: :string, description: "Suggested test name"},
        framework: %Schema{type: :string, description: "Test framework used"},
        imports: %Schema{
          type: :array,
          items: %Schema{type: :string},
          description: "Required imports"
        }
      },
      required: [:test_code]
    })
  end
end
