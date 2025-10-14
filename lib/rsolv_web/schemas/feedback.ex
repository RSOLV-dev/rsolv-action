defmodule RsolvWeb.Schemas.Feedback do
  @moduledoc """
  OpenAPI schemas for feedback endpoints.
  """

  alias OpenApiSpex.Schema

  defmodule FeedbackRequest do
    @moduledoc "Feedback submission request"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "FeedbackRequest",
      type: :object,
      description: "User feedback submission",
      properties: %{
        email: %Schema{
          type: :string,
          format: :email,
          description: "User's email address",
          example: "user@example.com"
        },
        message: %Schema{
          type: :string,
          description: "Feedback message content",
          example: "Great tool! Would love to see support for Go language."
        },
        content: %Schema{
          type: :string,
          description: "Alternative field name for message content",
          nullable: true
        },
        rating: %Schema{
          type: :integer,
          minimum: 1,
          maximum: 5,
          description: "User rating (1-5 stars)",
          nullable: true,
          example: 5
        },
        tags: %Schema{
          type: :array,
          items: %Schema{type: :string},
          description: "Categorization tags",
          nullable: true,
          example: ["feature-request", "languages"]
        },
        source: %Schema{
          type: :string,
          description: "Source of feedback submission",
          nullable: true,
          example: "website"
        }
      },
      required: [:email, :message],
      example: %{
        "email" => "user@example.com",
        "message" => "Love the automated fixes! Could you add Python support?",
        "rating" => 5,
        "tags" => ["feature-request", "python"],
        "source" => "api"
      }
    })
  end

  defmodule FeedbackResponse do
    @moduledoc "Feedback record response"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "FeedbackResponse",
      type: :object,
      description: "Stored feedback record",
      properties: %{
        id: %Schema{
          type: :string,
          format: :uuid,
          description: "Unique feedback identifier"
        },
        email: %Schema{type: :string, format: :email},
        message: %Schema{type: :string, description: "Feedback content"},
        rating: %Schema{type: :integer, nullable: true},
        tags: %Schema{type: :array, items: %Schema{type: :string}, nullable: true},
        source: %Schema{type: :string},
        created_at: %Schema{
          type: :string,
          format: :"date-time",
          description: "When feedback was submitted"
        }
      },
      required: [:id, :email, :message, :created_at],
      example: %{
        "id" => "550e8400-e29b-41d4-a716-446655440000",
        "email" => "user@example.com",
        "message" => "Love the automated fixes!",
        "rating" => 5,
        "tags" => ["feature-request"],
        "source" => "api",
        "created_at" => "2025-10-14T15:30:00Z"
      }
    })
  end

  defmodule FeedbackListResponse do
    @moduledoc "List of feedback entries"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "FeedbackListResponse",
      type: :object,
      description: "Collection of feedback entries",
      properties: %{
        data: %Schema{
          type: :array,
          items: FeedbackResponse,
          description: "Array of feedback entries"
        },
        total: %Schema{
          type: :integer,
          description: "Total number of feedback entries",
          example: 142
        }
      },
      required: [:data],
      example: %{
        "data" => [
          %{
            "id" => "550e8400-e29b-41d4-a716-446655440000",
            "email" => "user@example.com",
            "message" => "Great product!",
            "rating" => 5,
            "tags" => ["general"],
            "source" => "api",
            "created_at" => "2025-10-14T15:30:00Z"
          }
        ],
        "total" => 142
      }
    })
  end

  defmodule FeedbackStats do
    @moduledoc "Feedback statistics response"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "FeedbackStats",
      type: :object,
      description: "Aggregate feedback statistics",
      properties: %{
        total_feedback: %Schema{
          type: :integer,
          description: "Total number of feedback submissions",
          example: 142
        },
        rating_distribution: %Schema{
          type: :object,
          description: "Distribution of ratings (1-5 stars)",
          additionalProperties: %Schema{type: :integer},
          example: %{
            "5" => 78,
            "4" => 42,
            "3" => 15,
            "2" => 5,
            "1" => 2
          }
        },
        recent_feedback: %Schema{
          type: :array,
          items: %Schema{
            type: :object,
            properties: %{
              id: %Schema{type: :string, format: :uuid},
              email: %Schema{type: :string},
              message: %Schema{
                type: :string,
                description: "Truncated message (first 100 chars)"
              },
              rating: %Schema{type: :integer, nullable: true},
              created_at: %Schema{type: :string, format: :"date-time"}
            }
          },
          description: "Most recent 10 feedback submissions"
        },
        generated_at: %Schema{
          type: :string,
          format: :"date-time",
          description: "When statistics were generated"
        }
      },
      required: [:total_feedback, :rating_distribution, :recent_feedback, :generated_at]
    })
  end
end
