defmodule RsolvWeb.Schemas.Phase do
  @moduledoc """
  OpenAPI schemas for phase data storage endpoints (GitHub Actions multi-phase tracking).
  """

  alias OpenApiSpex.Schema

  defmodule PhaseStoreRequest do
    @moduledoc "Phase data storage request"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "PhaseStoreRequest",
      description: "Request to store phase execution data from RSOLV GitHub Action",
      type: :object,
      properties: %{
        phase: %Schema{
          type: :string,
          description: "Workflow phase",
          enum: ["scan", "validation", "mitigation"],
          example: "scan"
        },
        repo: %Schema{
          type: :string,
          description: "Repository in owner/name format",
          example: "octocat/hello-world"
        },
        commitSha: %Schema{
          type: :string,
          description: "Git commit SHA",
          example: "abc123def456"
        },
        branch: %Schema{
          type: :string,
          description: "Git branch (optional, for scan phase)",
          nullable: true,
          example: "main"
        },
        issueNumber: %Schema{
          type: :integer,
          description: "GitHub issue number (required for validation and mitigation phases)",
          nullable: true,
          example: 42
        },
        data: %Schema{
          type: :object,
          description: "Phase-specific data (structure varies by phase)",
          additionalProperties: true,
          example: %{
            "vulnerabilitiesFound" => 5,
            "issuesCreated" => 3
          }
        }
      },
      required: [:phase, :repo, :commitSha, :data],
      example: %{
        "phase" => "scan",
        "repo" => "octocat/hello-world",
        "commitSha" => "abc123def456",
        "branch" => "main",
        "data" => %{
          "vulnerabilitiesFound" => 5,
          "patternsUsed" => 120,
          "issuesCreated" => 3
        }
      }
    })
  end

  defmodule PhaseStoreResponse do
    @moduledoc "Phase data storage response"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "PhaseStoreResponse",
      description: "Confirmation of phase data storage",
      type: :object,
      properties: %{
        success: %Schema{
          type: :boolean,
          description: "Whether storage succeeded",
          example: true
        },
        id: %Schema{
          type: :string,
          description: "Phase data record ID",
          example: "phase_abc123"
        },
        phase: %Schema{
          type: :string,
          description: "Phase that was stored",
          example: "scan"
        }
      },
      required: [:success, :id, :phase],
      example: %{
        "success" => true,
        "id" => "phase_abc123",
        "phase" => "scan"
      }
    })
  end

  defmodule PhaseRetrieveResponse do
    @moduledoc "Phase data retrieval response"
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "PhaseRetrieveResponse",
      description: "Accumulated phase data from all workflow phases",
      type: :object,
      properties: %{
        scan: %Schema{
          type: :object,
          description: "SCAN phase data",
          nullable: true,
          additionalProperties: true,
          example: %{
            "vulnerabilitiesFound" => 5,
            "issuesCreated" => 3
          }
        },
        validation: %Schema{
          type: :object,
          description: "VALIDATION phase data",
          nullable: true,
          additionalProperties: true,
          example: %{
            "branchName" => "rsolv/fix-sql-injection",
            "testsGenerated" => 6,
            "validated" => true
          }
        },
        mitigation: %Schema{
          type: :object,
          description: "MITIGATION phase data",
          nullable: true,
          additionalProperties: true,
          example: %{
            "prUrl" => "https://github.com/octocat/hello-world/pull/123",
            "prNumber" => 123,
            "filesChanged" => 4
          }
        },
        repo: %Schema{
          type: :string,
          description: "Repository",
          example: "octocat/hello-world"
        },
        issue_number: %Schema{
          type: :integer,
          description: "GitHub issue number",
          example: 42
        },
        commit_sha: %Schema{
          type: :string,
          description: "Commit SHA",
          example: "abc123def456"
        }
      },
      example: %{
        "scan" => %{
          "vulnerabilitiesFound" => 5,
          "patternsUsed" => 120,
          "issuesCreated" => 3
        },
        "validation" => %{
          "branchName" => "rsolv/fix-sql-injection",
          "testsGenerated" => 6,
          "validated" => true
        },
        "mitigation" => %{
          "prUrl" => "https://github.com/octocat/hello-world/pull/123",
          "prNumber" => 123,
          "filesChanged" => 4,
          "fixes" => []
        },
        "repo" => "octocat/hello-world",
        "issue_number" => 42,
        "commit_sha" => "abc123def456"
      }
    })
  end
end
