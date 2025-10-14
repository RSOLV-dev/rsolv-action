defmodule RsolvWeb.Schemas.FixAttempt do
  @moduledoc """
  OpenAPI schemas for fix attempt tracking endpoints.
  """

  alias OpenApiSpex.Schema

  defmodule FixAttemptRequest do
    @moduledoc "Fix attempt creation request"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "FixAttemptRequest",
      type: :object,
      description: "Request to record a new fix attempt for billing and tracking",
      properties: %{
        github_org: %Schema{
          type: :string,
          description: "GitHub organization name",
          example: "RSOLV-dev"
        },
        repo_name: %Schema{
          type: :string,
          description: "Repository name",
          example: "nodegoat-vulnerability-demo"
        },
        pr_number: %Schema{
          type: :integer,
          description: "Pull request number",
          example: 42
        },
        status: %Schema{
          type: :string,
          enum: ["pending", "in_progress", "completed", "failed"],
          description: "Fix attempt status (defaults to 'pending')",
          nullable: true
        },
        vulnerability_count: %Schema{
          type: :integer,
          description: "Number of vulnerabilities addressed",
          nullable: true
        },
        metadata: %Schema{
          type: :object,
          description: "Additional metadata about the fix attempt",
          additionalProperties: true,
          nullable: true
        }
      },
      required: [:github_org, :repo_name, :pr_number],
      example: %{
        "github_org" => "RSOLV-dev",
        "repo_name" => "nodegoat-vulnerability-demo",
        "pr_number" => 42,
        "status" => "pending",
        "vulnerability_count" => 3
      }
    })
  end

  defmodule FixAttemptResponse do
    @moduledoc "Fix attempt record response"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "FixAttemptResponse",
      type: :object,
      description: "Recorded fix attempt details",
      properties: %{
        id: %Schema{
          type: :string,
          format: :uuid,
          description: "Unique fix attempt identifier"
        },
        status: %Schema{
          type: :string,
          enum: ["pending", "in_progress", "completed", "failed"],
          description: "Current fix attempt status"
        },
        github_org: %Schema{type: :string, description: "GitHub organization name"},
        repo_name: %Schema{type: :string, description: "Repository name"},
        pr_number: %Schema{type: :integer, description: "Pull request number"},
        billing_status: %Schema{
          type: :string,
          enum: ["unbilled", "billed", "credited"],
          description: "Billing status for this fix attempt"
        }
      },
      required: [:id, :status, :github_org, :repo_name, :pr_number, :billing_status],
      example: %{
        "id" => "550e8400-e29b-41d4-a716-446655440000",
        "status" => "pending",
        "github_org" => "RSOLV-dev",
        "repo_name" => "nodegoat-vulnerability-demo",
        "pr_number" => 42,
        "billing_status" => "unbilled"
      }
    })
  end

  defmodule ConflictError do
    @moduledoc "Fix attempt conflict error"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "ConflictError",
      type: :object,
      description: "Error response when fix attempt already exists",
      properties: %{
        error: %Schema{
          type: :string,
          description: "Error message",
          example: "Fix attempt already exists for this PR"
        }
      },
      required: [:error]
    })
  end
end
