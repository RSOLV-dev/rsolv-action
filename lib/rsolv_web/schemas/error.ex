defmodule RsolvWeb.Schemas.Error do
  @moduledoc """
  Common error response schemas for the API.
  """

  alias OpenApiSpex.Schema

  defmodule ErrorResponse do
    @moduledoc "Standard error response"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "ErrorResponse",
      description: "Standard error response structure",
      type: :object,
      properties: %{
        error: %Schema{type: :string, description: "Error type or code"},
        message: %Schema{type: :string, description: "Human-readable error message"},
        details: %Schema{
          type: :object,
          description: "Additional error details (optional)",
          nullable: true,
          additionalProperties: true
        }
      },
      required: [:error, :message],
      example: %{
        "error" => "unauthorized",
        "message" => "Invalid API key"
      }
    })
  end

  defmodule ValidationError do
    @moduledoc "Validation error with field-specific details"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "ValidationError",
      description: "Validation error with field-specific details",
      type: :object,
      properties: %{
        error: %Schema{type: :string, description: "Error type", example: "validation_error"},
        message: %Schema{type: :string, description: "General error message"},
        fields: %Schema{
          type: :object,
          description: "Field-specific error messages",
          additionalProperties: %Schema{
            type: :array,
            items: %Schema{type: :string}
          }
        }
      },
      required: [:error, :message],
      example: %{
        "error" => "validation_error",
        "message" => "Invalid request parameters",
        "fields" => %{
          "language" => ["is required"],
          "code" => ["cannot be empty"]
        }
      }
    })
  end

  defmodule RateLimitError do
    @moduledoc "Rate limit exceeded error"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "RateLimitError",
      description: "Rate limit exceeded error response",
      type: :object,
      properties: %{
        error: %Schema{type: :string, description: "Error type", example: "rate_limited"},
        message: %Schema{type: :string, description: "Error message"},
        retry_after: %Schema{
          type: :integer,
          description: "Seconds to wait before retrying",
          example: 3600
        }
      },
      required: [:error, :message, :retry_after],
      example: %{
        "error" => "rate_limited",
        "message" => "Rate limit exceeded. Please try again later.",
        "retry_after" => 3600
      }
    })
  end
end
